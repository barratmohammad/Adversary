"""Static cheat detector for implementations that game their tests (pure stdlib).

Finding kinds:
    hardcoded-answer  implementation special-cases specific input values
    test-detection    implementation checks whether it is running under a test runner
    exit-hack         sys.exit / os._exit / os.kill / builtins or pytest-hook monkeypatching
    vacuous-test      tests that cannot fail (no asserts, tautologies, swallowed asserts, skipped)
    test-tampering    conftest collection hooks, or tests monkeypatching the function under test

`detect_cheats` never raises on malformed input: files that do not parse are skipped
(a test file that does not parse yields one low-severity vacuous-test finding).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Hashable, Iterable


@dataclass
class CheatFinding:
    kind: str
    path: str
    lineno: int
    severity: str
    message: str
    evidence: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Literal helpers
# --------------------------------------------------------------------------- #

_TRIVIAL: frozenset = frozenset({0, 1, -1, "", None, True, False, ()})
_NOTHING = object()


def _literal_value(node: ast.AST | None) -> Any:
    """Hashable value of a literal expression (constants and containers of them),
    or _NOTHING when the node is not a pure literal."""
    if node is None:
        return _NOTHING
    if isinstance(node, ast.Constant):
        v = node.value
        if isinstance(v, (bytes, complex)):
            return repr(v)
        if v is Ellipsis:
            return "..."
        return v
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        inner = _literal_value(node.operand)
        if inner is _NOTHING or not isinstance(inner, (int, float)) or isinstance(inner, bool):
            return _NOTHING
        return -inner if isinstance(node.op, ast.USub) else inner
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        items = [_literal_value(e) for e in node.elts]
        if any(i is _NOTHING for i in items):
            return _NOTHING
        return tuple(items)
    if isinstance(node, ast.Dict):
        items = []
        for k, v in zip(node.keys, node.values):
            if k is None:
                return _NOTHING
            kv, vv = _literal_value(k), _literal_value(v)
            if kv is _NOTHING or vv is _NOTHING:
                return _NOTHING
            items.append((kv, vv))
        return ("<dict>", tuple(items))
    return _NOTHING


def _is_trivial(value: Any) -> bool:
    try:
        if value in _TRIVIAL:
            return True
    except TypeError:
        return False
    if isinstance(value, tuple) and len(value) == 0:
        return True
    if isinstance(value, tuple) and value and value[0] == "<dict>" and not value[1]:
        return True
    return False


def _jsonable(value: Any) -> Any:
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_jsonable(v) for v in value]
    return repr(value)


def _sorted_values(values: Iterable[Any]) -> list[Any]:
    return [_jsonable(v) for v in sorted(set(values), key=lambda v: (type(v).__name__, repr(v)))]


def _collect_literals(node: ast.AST) -> set[Hashable]:
    """All literal values (constants + container literals) inside `node`."""
    out: set[Hashable] = set()
    for sub in ast.walk(node):
        v = _literal_value(sub)
        if v is not _NOTHING:
            try:
                hash(v)
            except TypeError:
                continue
            out.add(v)
    return out


def _test_literals(trees: dict[str, ast.AST]) -> tuple[set[Hashable], set[Hashable]]:
    """(input literals from call args/parametrize, expected literals from asserts)."""
    inputs: set[Hashable] = set()
    expected: set[Hashable] = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                lits: set[Hashable] = set()
                for a in node.args:
                    lits |= _collect_literals(a)
                for kw in node.keywords:
                    lits |= _collect_literals(kw.value)
                inputs |= lits
                # parametrize rows hold both inputs and expected outputs
                if _call_name(node).endswith("parametrize"):
                    expected |= lits
            elif isinstance(node, ast.Assert):
                expected |= _collect_literals(node.test)
    return inputs, expected


_SPEC_NUM = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")
_SPEC_STR = re.compile(r"\"([^\"\n]*)\"|'([^'\n]*)'|`([^`\n]*)`")


def _spec_literals(spec: str) -> set[Hashable]:
    out: set[Hashable] = set()
    if not spec:
        return out
    for m in _SPEC_NUM.finditer(spec):
        txt = m.group(0)
        try:
            out.add(float(txt) if "." in txt else int(txt))
        except ValueError:
            pass
    for m in _SPEC_STR.finditer(spec):
        s = next(g for g in m.groups() if g is not None)
        if s:
            out.add(s)
            # also numbers quoted in the spec, e.g. "1994"
            if re.fullmatch(r"-?\d+", s):
                out.add(int(s))
    return out


# --------------------------------------------------------------------------- #
# Generic AST helpers
# --------------------------------------------------------------------------- #

def _dotted(node: ast.AST) -> str | None:
    """'a.b.c' for Name/Attribute chains, else None."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _call_name(node: ast.Call) -> str:
    return _dotted(node.func) or ""


def _func_body_nodes(func: ast.AST) -> Iterable[ast.AST]:
    """Walk a function body without descending into nested function/class defs."""
    stack = list(reversed(func.body))
    while stack:
        n = stack.pop()
        yield n
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(n))))


def _in_main_guard(tree: ast.AST) -> set[int]:
    skipped: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            t = node.test
            if isinstance(t, ast.Compare) and any(
                isinstance(s, ast.Name) and s.id == "__name__" for s in [t.left, *t.comparators]
            ):
                for n in ast.walk(node):
                    skipped.add(id(n))
    return skipped


def _parse_all(files: dict[str, str]) -> tuple[dict[str, ast.AST], list[str]]:
    trees: dict[str, ast.AST] = {}
    broken: list[str] = []
    for path, src in files.items():
        try:
            trees[path] = ast.parse(src, filename=path)
        except (SyntaxError, ValueError, TypeError, RecursionError):
            broken.append(path)
    return trees, broken


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    a = func.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return {n for n in names if n not in ("self", "cls")}


# --------------------------------------------------------------------------- #
# 1. hardcoded-answer
# --------------------------------------------------------------------------- #

def _param_eq_literals(test: ast.AST, params: set[str]) -> list[Hashable]:
    """Literal values a raw parameter is compared against for equality in `test`.
    Handles `p == lit`, `lit == p`, `p in (lits)`, `(p, q) == (l1, l2)`, and `and`
    conjunctions of those. Returns [] when the test is not of that shape."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        vals: list[Hashable] = []
        for v in test.values:
            vals.extend(_param_eq_literals(v, params))
        return vals
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return []
    op = test.ops[0]
    left, right = test.left, test.comparators[0]

    def is_param(n: ast.AST) -> bool:
        if isinstance(n, ast.Name) and n.id in params:
            return True
        return isinstance(n, ast.Tuple) and bool(n.elts) and all(is_param(e) for e in n.elts)

    if isinstance(op, ast.Eq):
        if is_param(left):
            v = _literal_value(right)
        elif is_param(right):
            v = _literal_value(left)
        else:
            return []
        return [] if v is _NOTHING else [v]
    if isinstance(op, ast.In) and is_param(left) and isinstance(right, (ast.Tuple, ast.List, ast.Set)):
        vals = [_literal_value(e) for e in right.elts]
        return [v for v in vals if v is not _NOTHING]
    return []


def _returned_literal(body: list[ast.stmt]) -> Any:
    """Literal returned by a branch body (first statement a `return <literal>`)."""
    if body and isinstance(body[0], ast.Return):
        return _literal_value(body[0].value)
    return _NOTHING


def _dict_literal_keys(node: ast.AST) -> list[Hashable] | None:
    if not isinstance(node, ast.Dict):
        return None
    keys = []
    for k in node.keys:
        v = _literal_value(k)
        if v is _NOTHING:
            return None
        keys.append(v)
    return keys


def _detect_hardcoded(path: str, tree: ast.AST, inputs: set[Hashable],
                      expected: set[Hashable], spec_lits: set[Hashable]) -> list[CheatFinding]:
    findings: list[CheatFinding] = []
    known_inputs = inputs | spec_lits

    # module-level literal dict tables: name -> (keys, lineno)
    tables: dict[str, tuple[list[Hashable], int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            keys = _dict_literal_keys(node.value)
            if keys is not None and len(keys) >= 2:
                tables[node.targets[0].id] = (keys, node.lineno)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            keys = _dict_literal_keys(node.value)
            if keys is not None and len(keys) >= 2:
                tables[node.target.id] = (keys, node.lineno)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = _param_names(func)
        if not params:
            continue

        # --- if/elif chains and match statements -------------------------
        cases: list[tuple[Hashable, Any, int]] = []  # (input literal, returned literal, lineno)
        for node in _func_body_nodes(func):
            if isinstance(node, ast.If):
                lits = _param_eq_literals(node.test, params)
                if lits:
                    ret = _returned_literal(node.body)
                    if ret is not _NOTHING:
                        for lit in lits:
                            cases.append((lit, ret, node.lineno))
            elif isinstance(node, ast.Match) and isinstance(node.subject, ast.Name) \
                    and node.subject.id in params:
                for case in node.cases:
                    pat = case.pattern
                    lit: Any = _NOTHING
                    if isinstance(pat, ast.MatchValue):
                        lit = _literal_value(pat.value)
                    elif isinstance(pat, ast.MatchSingleton):
                        lit = pat.value
                    if lit is _NOTHING:
                        continue
                    ret = _returned_literal(case.body)
                    if ret is not _NOTHING:
                        cases.append((lit, ret, case.pattern.lineno))

        nontrivial = [(i, r, ln) for (i, r, ln) in cases if not _is_trivial(i)]
        if nontrivial:
            in_vals = {i for i, _, _ in nontrivial}
            overlap_in = {v for v in in_vals if v in known_inputs}
            ret_vals = {r for _, r, _ in nontrivial if not _is_trivial(r)}
            overlap_out = {v for v in ret_vals if v in expected}
            strong_single = len(in_vals) == 1 and overlap_in and overlap_out
            if len(in_vals) >= 2 or strong_single:
                severity = "high" if overlap_in else "medium"
                lineno = min(ln for _, _, ln in nontrivial)
                shown = _sorted_values(overlap_in or in_vals)
                if overlap_in:
                    msg = (f"{func.name} special-cases inputs {shown} which appear in the "
                           f"tests/spec; returns hardcoded literals")
                else:
                    msg = f"{func.name} special-cases {len(in_vals)} literal inputs {shown} and returns hardcoded literals"
                findings.append(CheatFinding(
                    "hardcoded-answer", path, lineno, severity, msg,
                    {"function": func.name, "inputs": _sorted_values(in_vals),
                     "overlap": _sorted_values(overlap_in),
                     "returns": _sorted_values(ret_vals),
                     "returns_overlap": _sorted_values(overlap_out)},
                ))

        # --- lookup tables indexed by the raw parameter ------------------
        local_tables = dict(tables)
        for node in _func_body_nodes(func):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                keys = _dict_literal_keys(node.value)
                if keys is not None and len(keys) >= 2:
                    local_tables[node.targets[0].id] = (keys, node.lineno)

        def table_keys_for(expr: ast.AST) -> tuple[list[Hashable], str] | None:
            if isinstance(expr, ast.Name) and expr.id in local_tables:
                return local_tables[expr.id][0], expr.id
            keys = _dict_literal_keys(expr)
            if keys is not None and len(keys) >= 2:
                return keys, "<inline dict>"
            return None

        def is_raw_param(expr: ast.AST) -> bool:
            return isinstance(expr, ast.Name) and expr.id in params

        hits: list[tuple[list[Hashable], str, int]] = []
        for node in _func_body_nodes(func):
            if isinstance(node, ast.Subscript) and is_raw_param(node.slice):
                tk = table_keys_for(node.value)
                if tk:
                    hits.append((tk[0], tk[1], node.lineno))
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "get" and node.args and is_raw_param(node.args[0]):
                tk = table_keys_for(node.func.value)
                if tk:
                    hits.append((tk[0], tk[1], node.lineno))
        for keys, name, lineno in hits:
            key_set = {k for k in keys if not _is_trivial(k)}
            overlap = {k for k in key_set if k in known_inputs}
            if len(overlap) >= 3 or (len(overlap) >= 2 and len(overlap) == len(key_set)):
                findings.append(CheatFinding(
                    "hardcoded-answer", path, lineno, "high",
                    f"{func.name} looks up the raw argument in table {name} whose keys "
                    f"{_sorted_values(overlap)} are the test/spec inputs",
                    {"function": func.name, "table": name, "keys": _sorted_values(key_set),
                     "overlap": _sorted_values(overlap)},
                ))
                break  # one finding per function for tables

    return findings


# --------------------------------------------------------------------------- #
# 2. test-detection   3. exit-hack
# --------------------------------------------------------------------------- #

_FRAME_CALLS = {
    "sys._getframe", "inspect.stack", "inspect.currentframe", "inspect.getouterframes",
    "traceback.extract_stack", "traceback.format_stack",
}
_TEST_STRINGS = ("pytest_current_test", "pytest", "unittest", "_pytest", "hypothesis")
_EXIT_CALLS = {"sys.exit", "os._exit", "os.kill", "os.abort", "pytest.exit", "exit", "quit"}
_REPORT_HOOKS = {
    "pytest_runtest_makereport", "pytest_runtest_call", "pytest_pyfunc_call",
    "pytest_runtest_protocol", "pytest_exception_interact", "pytest_assertrepr_compare",
    "pytest_runtest_logreport", "pytest_report_teststatus", "pytest_sessionfinish",
    "pytest_terminal_summary",
}
_COLLECTION_HOOKS = {
    "pytest_collection_modifyitems", "pytest_ignore_collect", "pytest_pycollect_makeitem",
    "pytest_collect_file", "pytest_itemcollected", "pytest_deselected", "pytest_runtest_setup",
    "pytest_collection_finish", "pytest_collection",
}
_BUILTIN_PATCH_TARGETS = {"AssertionError", "assert", "__import__", "isinstance", "eval", "exec"}


def _detect_test_detection(path: str, tree: ast.AST) -> list[CheatFinding]:
    findings: list[CheatFinding] = []
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    def ancestors_text(node: ast.AST, depth: int = 4) -> str:
        n = node
        for _ in range(depth):
            p = parents.get(id(n))
            if p is None or isinstance(p, ast.stmt):
                n = p or n
                break
            n = p
        try:
            return ast.unparse(n)
        except Exception:
            return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _FRAME_CALLS:
                findings.append(CheatFinding(
                    "test-detection", path, node.lineno, "high",
                    f"implementation inspects the call stack via {name}()",
                    {"call": name}))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            low = node.value.lower()
            if any(s in low for s in _TEST_STRINGS):
                ctx = ancestors_text(node)
                env_like = any(k in ctx for k in ("sys.modules", "os.environ", "sys.argv",
                                                   "environ", "modules", "getenv"))
                if env_like:
                    findings.append(CheatFinding(
                        "test-detection", path, node.lineno, "high",
                        f"implementation checks for {node.value!r} in the environment/modules",
                        {"string": node.value, "context": ctx[:120]}))
                elif "pytest_current_test" in low:
                    findings.append(CheatFinding(
                        "test-detection", path, node.lineno, "high",
                        "implementation references the PYTEST_CURRENT_TEST marker",
                        {"string": node.value, "context": ctx[:120]}))
                # a bare 'pytest'/'unittest' substring elsewhere (docstrings, log text)
                # is not evidence on its own and is deliberately not reported
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
            for m in mods:
                root = m.split(".")[0]
                if root in ("pytest", "_pytest", "unittest"):
                    findings.append(CheatFinding(
                        "test-detection", path, node.lineno, "medium",
                        f"implementation imports test framework {root!r}", {"module": m}))
    return findings


def _detect_exit_hacks(path: str, tree: ast.AST, is_test: bool) -> list[CheatFinding]:
    findings: list[CheatFinding] = []
    skipped = _in_main_guard(tree)
    for node in ast.walk(tree):
        if id(node) in skipped:
            continue
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in _EXIT_CALLS:
                findings.append(CheatFinding(
                    "exit-hack", path, node.lineno, "high",
                    f"{'test' if is_test else 'implementation'} calls {name}()", {"call": name}))
            elif name in ("setattr", "monkeypatch.setattr", "mock.patch.object", "patch.object") and node.args:
                target = _dotted(node.args[0]) or ""
                attr = node.args[1].value if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) else ""
                if target in ("builtins", "__builtins__") or attr in _BUILTIN_PATCH_TARGETS:
                    findings.append(CheatFinding(
                        "exit-hack", path, node.lineno, "high",
                        f"monkeypatches builtins ({target}.{attr})", {"target": target, "attr": attr}))
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                d = _dotted(t) or ""
                if d.startswith(("builtins.", "__builtins__.")) or d in _BUILTIN_PATCH_TARGETS \
                        or (isinstance(t, ast.Subscript) and (_dotted(t.value) or "") in ("__builtins__", "builtins.__dict__")):
                    findings.append(CheatFinding(
                        "exit-hack", path, node.lineno, "high",
                        f"assigns to builtin {d or ast.unparse(t)}", {"target": d or ast.unparse(t)}))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _REPORT_HOOKS:
            findings.append(CheatFinding(
                "exit-hack", path, node.lineno, "high",
                f"overrides pytest hook {node.name}", {"hook": node.name}))
    return findings


# --------------------------------------------------------------------------- #
# 4. vacuous-test
# --------------------------------------------------------------------------- #

_SKIP_DECORATORS = ("skip", "skipif", "xfail", "skipUnless", "skipIf", "expectedFailure")
_WEAK_CALLS = {"isinstance", "hasattr", "callable"}


def _is_assert_like_call(call: ast.Call) -> bool:
    name = _call_name(call)
    last = name.rsplit(".", 1)[-1]
    if name in ("pytest.raises", "pytest.warns", "pytest.fail", "raises", "warns", "fail",
                "assertRaises", "assertRaisesRegex", "pytest.approx"):
        return True
    if "assert" in last.lower() or last.startswith(("check_", "verify_", "expect_")) \
            or last in ("check", "verify", "expect"):
        return True
    return False


def _is_tautology(test: ast.AST) -> bool:
    if isinstance(test, ast.Constant):
        return bool(test.value)
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        try:
            l, r = ast.unparse(test.left), ast.unparse(test.comparators[0])
        except Exception:
            return False
        if l == r and isinstance(test.ops[0], (ast.Eq, ast.Is, ast.LtE, ast.GtE)):
            return True
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        return any(_is_tautology(v) for v in test.values)
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.GtE) \
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == 0 \
            and isinstance(test.left, ast.Call) and _call_name(test.left) == "len":
        return True
    return False


def _is_weak(test: ast.AST) -> bool:
    if isinstance(test, ast.Call) and _call_name(test) in _WEAK_CALLS:
        return True
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], (ast.IsNot, ast.Is)) \
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None:
        return True
    if isinstance(test, ast.Name):  # `assert result`
        return True
    return False


def _swallows_assertion(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        broad = True
    else:
        names = [_dotted(n) or "" for n in (handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type])]
        broad = any(n in ("AssertionError", "Exception", "BaseException") for n in names)
    if not broad:
        return False
    for n in ast.walk(handler):
        if isinstance(n, ast.Raise):
            return False
        if isinstance(n, ast.Call) and _call_name(n) in ("pytest.fail", "fail", "self.fail"):
            return False
    return True


def _detect_vacuous(path: str, tree: ast.AST) -> list[CheatFinding]:
    findings: list[CheatFinding] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)) or not func.name.startswith("test"):
            continue
        # skip / xfail markers
        for dec in func.decorator_list:
            d = _dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
            if d.rsplit(".", 1)[-1] in _SKIP_DECORATORS:
                findings.append(CheatFinding(
                    "vacuous-test", path, getattr(dec, "lineno", func.lineno), "medium",
                    f"{func.name} is marked {d.rsplit('.', 1)[-1]} and will not fail", {"decorator": d}))

        asserts: list[ast.Assert] = []
        assert_calls = 0
        skip_calls = 0
        swallowed = False
        for node in _func_body_nodes(func):
            if isinstance(node, ast.Assert):
                asserts.append(node)
            elif isinstance(node, ast.Call):
                if _is_assert_like_call(node):
                    assert_calls += 1
                elif _call_name(node) in ("pytest.skip", "skip", "pytest.xfail", "self.skipTest"):
                    skip_calls += 1
            elif isinstance(node, ast.Try):
                if any(isinstance(n, ast.Assert) for h in [node.body] for s in h for n in ast.walk(s)) \
                        and any(_swallows_assertion(h) for h in node.handlers):
                    swallowed = True
                    findings.append(CheatFinding(
                        "vacuous-test", path, node.lineno, "medium",
                        f"{func.name} wraps its assertions in try/except that swallows failures", {}))
        if skip_calls:
            findings.append(CheatFinding(
                "vacuous-test", path, func.lineno, "medium",
                f"{func.name} calls skip/xfail at runtime", {}))

        if not asserts and assert_calls == 0:
            if not skip_calls:
                findings.append(CheatFinding(
                    "vacuous-test", path, func.lineno, "medium",
                    f"{func.name} has no assertions", {}))
            continue
        if swallowed or assert_calls:
            continue
        taut = [a for a in asserts if _is_tautology(a.test)]
        weak = [a for a in asserts if _is_weak(a.test)]
        if len(taut) == len(asserts):
            findings.append(CheatFinding(
                "vacuous-test", path, asserts[0].lineno, "medium",
                f"{func.name} only asserts tautologies ({ast.unparse(asserts[0].test)})",
                {"asserts": [ast.unparse(a.test) for a in asserts]}))
        elif len(taut) + len(weak) == len(asserts):
            findings.append(CheatFinding(
                "vacuous-test", path, asserts[0].lineno, "low",
                f"{func.name} only makes weak assertions (is not None / isinstance)",
                {"asserts": [ast.unparse(a.test) for a in asserts]}))
    return findings


# --------------------------------------------------------------------------- #
# 5. test-tampering
# --------------------------------------------------------------------------- #

def _impl_function_names(impl_trees: dict[str, ast.AST]) -> set[str]:
    names: set[str] = set()
    for tree in impl_trees.values():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
    return names


def _detect_tampering(path: str, tree: ast.AST, impl_names: set[str], impl_modules: set[str]) -> list[CheatFinding]:
    findings: list[CheatFinding] = []
    is_conftest = path.replace("\\", "/").rsplit("/", 1)[-1] == "conftest.py"
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in _COLLECTION_HOOKS:
            findings.append(CheatFinding(
                "test-tampering", path, node.lineno, "high",
                f"{'conftest' if is_conftest else path} defines collection hook {node.name}",
                {"hook": node.name}))
        elif is_conftest and isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in ("collect_ignore", "collect_ignore_glob") for t in node.targets):
            findings.append(CheatFinding(
                "test-tampering", path, node.lineno, "high",
                "conftest sets collect_ignore", {}))
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            last = name.rsplit(".", 1)[-1]
            target_attr: str | None = None
            target_obj = ""
            if last == "setattr" and len(node.args) >= 2:
                a0, a1 = node.args[0], node.args[1]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and "." in a0.value:
                    target_obj, target_attr = a0.value.rsplit(".", 1)
                elif isinstance(a1, ast.Constant) and isinstance(a1.value, str):
                    target_obj, target_attr = _dotted(a0) or "", a1.value
            elif last == "patch" and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) and "." in node.args[0].value:
                target_obj, target_attr = node.args[0].value.rsplit(".", 1)
            elif last == "object" and name.endswith("patch.object") and len(node.args) >= 2 \
                    and isinstance(node.args[1], ast.Constant):
                target_obj, target_attr = _dotted(node.args[0]) or "", node.args[1].value
            if target_attr and target_attr in impl_names:
                findings.append(CheatFinding(
                    "test-tampering", path, node.lineno, "high",
                    f"test monkeypatches function under test {target_obj}.{target_attr}",
                    {"target": target_obj, "attr": target_attr}))
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and t.attr in impl_names:
                    base = _dotted(t.value) or ""
                    if base.split(".")[-1] in impl_modules:
                        findings.append(CheatFinding(
                            "test-tampering", path, node.lineno, "high",
                            f"test overwrites function under test {base}.{t.attr}",
                            {"target": base, "attr": t.attr}))
    return findings


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def detect_cheats(impl_files: dict[str, str], test_files: dict[str, str], spec: str = "") -> list[CheatFinding]:
    """Run every heuristic over the implementation and test sources.

    Never raises: unparsable implementation files are skipped, unparsable test
    files yield one low-severity vacuous-test finding.
    """
    findings: list[CheatFinding] = []
    try:
        impl_trees, _ = _parse_all(impl_files or {})
        test_trees, broken_tests = _parse_all(test_files or {})
        for path in broken_tests:
            findings.append(CheatFinding(
                "vacuous-test", path, 1, "low", "test file does not parse; none of its tests can run", {}))

        inputs, expected = _test_literals(test_trees)
        spec_lits = _spec_literals(spec or "")
        impl_names = _impl_function_names(impl_trees)
        impl_modules = {p.replace("\\", "/").rsplit("/", 1)[-1].removesuffix(".py") for p in impl_trees}

        for path, tree in impl_trees.items():
            for fn in (
                lambda: _detect_hardcoded(path, tree, inputs, expected, spec_lits),
                lambda: _detect_test_detection(path, tree),
                lambda: _detect_exit_hacks(path, tree, is_test=False),
            ):
                try:
                    findings.extend(fn())
                except Exception:
                    continue
        for path, tree in test_trees.items():
            for fn in (
                lambda: _detect_vacuous(path, tree),
                lambda: _detect_exit_hacks(path, tree, is_test=True),
                lambda: _detect_tampering(path, tree, impl_names, impl_modules),
            ):
                try:
                    findings.extend(fn())
                except Exception:
                    continue
    except Exception:
        return findings

    # de-duplicate identical findings, then order by severity, path, line
    seen: set[tuple] = set()
    unique: list[CheatFinding] = []
    for f in findings:
        key = (f.kind, f.path, f.lineno, f.message)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 3), f.path, f.lineno, f.kind))
    return unique


__all__ = ["CheatFinding", "detect_cheats"]
