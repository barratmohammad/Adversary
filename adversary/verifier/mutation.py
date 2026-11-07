"""AST-based mutation engine (pure stdlib).

`generate_mutants(path, source)` enumerates single-point mutations of a Python
module in a stable order, applies each one to a deep copy of the AST, and returns
only mutants whose source compiles and differs from the original.

Operator codes:
    AOR  arithmetic operator replacement   (+ <-> -, * <-> /, // <-> /, % -> //, ** -> *)
    ROR  relational operator replacement   (< <-> <=, > <-> >=, == <-> !=, < <-> >,
                                            in <-> not in, is <-> is not)
    LCR  logical connector replacement     (and <-> or)
    UOI  unary operator removal            (not x -> x)
    CRP  constant replacement              (n -> n+1 / n-1, True <-> False, "s" -> "")
    RVR  return value replacement          (return x -> return None)
    AAR  augmented assignment replacement  (+= <-> -=, *= <-> /=)
    SBR  statement replacement             (break <-> continue)
    IDX  index off-by-one                  (a[2] -> a[3] / a[1], a[1:3] -> a[2:3] ...)
"""

from __future__ import annotations

import ast
import random
from dataclasses import dataclass
from typing import Callable, Iterator


@dataclass(frozen=True)
class Mutant:
    id: str
    path: str
    lineno: int
    col: int
    op: str
    description: str
    source: str


# --------------------------------------------------------------------------- #
# Operator tables
# --------------------------------------------------------------------------- #

_BINOP_SWAPS: dict[type, list[type]] = {
    ast.Add: [ast.Sub],
    ast.Sub: [ast.Add],
    ast.Mult: [ast.Div],
    ast.Div: [ast.Mult, ast.FloorDiv],
    ast.FloorDiv: [ast.Div],
    ast.Mod: [ast.FloorDiv],
    ast.Pow: [ast.Mult],
}

_AUGASSIGN_SWAPS: dict[type, list[type]] = {
    ast.Add: [ast.Sub],
    ast.Sub: [ast.Add],
    ast.Mult: [ast.Div],
    ast.Div: [ast.Mult],
}

_CMPOP_SWAPS: dict[type, list[type]] = {
    ast.Lt: [ast.LtE, ast.Gt],
    ast.LtE: [ast.Lt],
    ast.Gt: [ast.GtE, ast.Lt],
    ast.GtE: [ast.Gt],
    ast.Eq: [ast.NotEq],
    ast.NotEq: [ast.Eq],
    ast.In: [ast.NotIn],
    ast.NotIn: [ast.In],
    ast.Is: [ast.IsNot],
    ast.IsNot: [ast.Is],
}

_OP_SYMBOL: dict[type, str] = {
    ast.Add: "+", ast.Sub: "-", ast.Mult: "*", ast.Div: "/", ast.FloorDiv: "//",
    ast.Mod: "%", ast.Pow: "**",
    ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=", ast.Eq: "==", ast.NotEq: "!=",
    ast.In: "in", ast.NotIn: "not in", ast.Is: "is", ast.IsNot: "is not",
    ast.And: "and", ast.Or: "or",
}


def _sym(op: ast.AST | type) -> str:
    t = op if isinstance(op, type) else type(op)
    return _OP_SYMBOL.get(t, t.__name__)


# --------------------------------------------------------------------------- #
# Candidate enumeration
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Candidate:
    node: ast.AST               # target node in the (shared) original tree
    stmt_index: int             # index of the enclosing top-level statement in tree.body
    lineno: int
    col: int
    op: str
    detail: str                 # short, id-safe detail e.g. "<->>="
    description: str
    func: str                   # enclosing function (or "<module>") for spreading
    transform: Callable[[ast.AST], ast.AST]   # returns node (maybe new) to put in place


def _is_main_guard(node: ast.AST) -> bool:
    if not isinstance(node, ast.If):
        return False
    t = node.test
    if not (isinstance(t, ast.Compare) and len(t.ops) == 1 and isinstance(t.ops[0], ast.Eq)):
        return False
    sides = [t.left, t.comparators[0]]
    has_name = any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
    has_main = any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides)
    return has_name and has_main


def _is_docstring_stmt(stmt: ast.AST) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and isinstance(stmt.value.value, str)
    )


def _skipped_nodes(tree: ast.AST) -> set[int]:
    """ids of nodes (and all their descendants) that must not be mutated."""
    roots: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and _is_docstring_stmt(body[0]):
                roots.append(body[0])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            roots.extend(node.decorator_list)
            if node.returns is not None:
                roots.append(node.returns)
            args = node.args
            for a in args.posonlyargs + args.args + args.kwonlyargs:
                if a.annotation is not None:
                    roots.append(a.annotation)
            for a in (args.vararg, args.kwarg):
                if a is not None and a.annotation is not None:
                    roots.append(a.annotation)
        if isinstance(node, ast.ClassDef):
            roots.extend(node.decorator_list)
        if isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
        if _is_main_guard(node):
            roots.append(node)
        if isinstance(node, ast.JoinedStr):
            # f-string pieces: leave the literal fragments alone
            roots.extend(v for v in node.values if isinstance(v, ast.Constant))
    skipped: set[int] = set()
    for r in roots:
        for n in ast.walk(r):
            skipped.add(id(n))
    return skipped


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Map id(node) -> qualified name of innermost enclosing function."""
    result: dict[int, str] = {}

    def visit(node: ast.AST, stack: list[str]) -> None:
        name = "<module>" if not stack else ".".join(stack)
        result[id(node)] = name
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            stack = stack + [node.name]
        for child in ast.iter_child_nodes(node):
            visit(child, stack)

    visit(tree, [])
    return result


def _parent_subscript_index(node: ast.AST, parents: dict[int, tuple[ast.AST, str, int | None]]) -> bool:
    """True if `node` is an int constant acting as a subscript index / slice bound."""
    p = parents.get(id(node))
    if p is None:
        return False
    parent, field, _ = p
    if isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.USub):
        node, p = parent, parents.get(id(parent))
        if p is None:
            return False
        parent, field, _ = p
    if isinstance(parent, ast.Subscript) and field == "slice":
        return True
    if isinstance(parent, ast.Slice) and field in ("lower", "upper"):
        return True
    return False


def _parent_map(tree: ast.AST) -> dict[int, tuple[ast.AST, str, int | None]]:
    parents: dict[int, tuple[ast.AST, str, int | None]] = {}
    for node in ast.walk(tree):
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        parents[id(item)] = (node, field, i)
            elif isinstance(value, ast.AST):
                parents[id(value)] = (node, field, None)
    return parents


def _int_constant(node: ast.AST) -> int | None:
    """Return int value for Constant(int) or -Constant(int); None otherwise."""
    if isinstance(node, ast.Constant) and type(node.value) is int:
        return node.value
    return None


def _candidates(tree: ast.AST) -> list[_Candidate]:
    skipped = _skipped_nodes(tree)
    funcs = _enclosing_functions(tree)
    parents = _parent_map(tree)
    top: dict[int, int] = {}
    for i, stmt in enumerate(getattr(tree, "body", [])):
        for n in ast.walk(stmt):
            top[id(n)] = i
    cands: list[_Candidate] = []

    def add(node: ast.AST, op: str, detail: str, description: str,
            transform: Callable[[ast.AST], ast.AST]) -> None:
        lineno = getattr(node, "lineno", 0)
        col = getattr(node, "col_offset", 0)
        cands.append(_Candidate(node, top.get(id(node), -1), lineno, col, op, detail,
                                f"{description} at line {lineno}", funcs[id(node)], transform))

    for node in ast.walk(tree):
        if id(node) in skipped:
            continue

        # AOR -------------------------------------------------------------
        if isinstance(node, ast.BinOp):
            for new in _BINOP_SWAPS.get(type(node.op), []):
                def t(n, new=new):
                    n.op = new()
                    return n
                add(node, "AOR", f"{_sym(node.op)}->{_sym(new)}",
                    f"replaced {_sym(node.op)} with {_sym(new)}", t)

        # ROR -------------------------------------------------------------
        elif isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                for new in _CMPOP_SWAPS.get(type(op), []):
                    def t(n, i=i, new=new):
                        n.ops[i] = new()
                        return n
                    suffix = f"#{i}" if len(node.ops) > 1 else ""
                    add(node, "ROR", f"{_sym(op)}->{_sym(new)}{suffix}",
                        f"replaced {_sym(op)} with {_sym(new)}", t)

        # LCR -------------------------------------------------------------
        elif isinstance(node, ast.BoolOp):
            new = ast.Or if isinstance(node.op, ast.And) else ast.And
            def t(n, new=new):
                n.op = new()
                return n
            add(node, "LCR", f"{_sym(node.op)}->{_sym(new)}",
                f"replaced {_sym(node.op)} with {_sym(new)}", t)

        # UOI (remove not) ------------------------------------------------
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            def t(n):
                return ast.copy_location(n.operand, n)
            add(node, "UOI", "del-not", "removed `not`", t)

        # CRP -------------------------------------------------------------
        elif isinstance(node, ast.Constant):
            v = node.value
            if _parent_subscript_index(node, parents):
                pass  # handled by IDX
            elif type(v) is bool:
                def t(n):
                    n.value = not n.value
                    return n
                add(node, "CRP", f"{v}->{not v}", f"replaced {v} with {not v}", t)
            elif type(v) is int:
                for delta in (1, -1):
                    def t(n, delta=delta):
                        n.value = n.value + delta
                        return n
                    add(node, "CRP", f"{v}->{v + delta}", f"replaced {v} with {v + delta}", t)
            elif type(v) is str and v != "":
                def t(n):
                    n.value = ""
                    return n
                add(node, "CRP", "str->empty", f"replaced {v!r} with ''", t)

        # RVR -------------------------------------------------------------
        elif isinstance(node, ast.Return):
            if node.value is not None and not (
                isinstance(node.value, ast.Constant) and node.value.value is None
            ):
                def t(n):
                    n.value = ast.Constant(value=None)
                    return n
                add(node, "RVR", "ret-None", "replaced return value with None", t)

        # AAR -------------------------------------------------------------
        elif isinstance(node, ast.AugAssign):
            for new in _AUGASSIGN_SWAPS.get(type(node.op), []):
                def t(n, new=new):
                    n.op = new()
                    return n
                add(node, "AAR", f"{_sym(node.op)}=->{_sym(new)}=",
                    f"replaced {_sym(node.op)}= with {_sym(new)}=", t)

        # SBR -------------------------------------------------------------
        elif isinstance(node, ast.Break):
            add(node, "SBR", "break->continue", "replaced break with continue",
                lambda n: ast.copy_location(ast.Continue(), n))
        elif isinstance(node, ast.Continue):
            add(node, "SBR", "continue->break", "replaced continue with break",
                lambda n: ast.copy_location(ast.Break(), n))

        # IDX -------------------------------------------------------------
        elif isinstance(node, ast.Subscript):
            targets: list[tuple[str, ast.AST]] = []
            sl = node.slice
            if isinstance(sl, ast.Slice):
                for name in ("lower", "upper"):
                    b = getattr(sl, name)
                    if b is not None:
                        targets.append((name, b))
            else:
                targets.append(("index", sl))
            for name, target in targets:
                # resolve int constant or negated int constant
                neg = isinstance(target, ast.UnaryOp) and isinstance(target.op, ast.USub)
                const_node = target.operand if neg else target
                base = _int_constant(const_node)
                if base is None:
                    continue
                value = -base if neg else base
                for delta in (1, -1):
                    new_value = value + delta
                    def t(n, name=name, new_value=new_value):
                        new_node = (ast.UnaryOp(op=ast.USub(), operand=ast.Constant(value=-new_value))
                                    if new_value < 0 else ast.Constant(value=new_value))
                        if name == "index":
                            n.slice = new_node
                        else:
                            # replace the whole Slice so only `n` itself is modified
                            old = n.slice
                            fields = {"lower": old.lower, "upper": old.upper, "step": old.step}
                            fields[name] = new_node
                            n.slice = ast.copy_location(ast.Slice(**fields), old)
                        return n
                    add(node, "IDX", f"{name}:{value}->{new_value}",
                        f"replaced {name} {value} with {new_value} in subscript", t)

    return cands


# --------------------------------------------------------------------------- #
# Applying mutations
# --------------------------------------------------------------------------- #

def _join_parts(body: list[ast.stmt], parts: list[str]) -> str:
    """Join per-statement unparses the way ast.unparse(Module) lays them out:
    one newline between statements, a blank line before def/class statements."""
    out: list[str] = []
    for i, (stmt, text) in enumerate(zip(body, parts)):
        if i:
            out.append("\n\n" if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else "\n")
        out.append(text)
    return "".join(out)


def _split_parts(tree: ast.Module, original: str) -> list[str] | None:
    """Per-top-level-statement unparses, or None if re-joining them would not
    reproduce `original` exactly (then callers fall back to a full unparse)."""
    try:
        parts = [ast.unparse(s) for s in tree.body]
    except Exception:
        return None
    body = tree.body
    if body and _is_docstring_stmt(body[0]):
        # A module docstring is rendered with triple quotes only in module context,
        # so take its text straight from the original (it is never mutated anyway).
        if len(body) == 1:
            parts[0] = original
        else:
            sep = "\n\n" if isinstance(body[1], (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else "\n"
            tail = sep + _join_parts(body[1:], parts[1:])
            if not original.endswith(tail):
                return None
            parts[0] = original[: len(original) - len(tail)]
    return parts if _join_parts(body, parts) == original else None


def _apply(tree: ast.Module, cand: _Candidate,
           parents: dict[int, tuple[ast.AST, str, int | None]],
           parts: list[str] | None) -> str:
    """Apply `cand` to the shared tree in place, unparse, then restore the tree.

    Transforms only ever modify attributes of the target node itself or return a
    replacement node, so a shallow snapshot of the target's fields (lists copied)
    plus the parent slot is enough to undo the change. This avoids a deep copy
    of the whole module per mutant. When `parts` is available only the affected
    top-level statement is re-unparsed.
    """
    target = cand.node
    snapshot = {k: (list(v) if isinstance(v, list) else v) for k, v in vars(target).items()}
    parent, field, idx = parents[id(target)]
    try:
        replacement = cand.transform(target)
        if replacement is not target:
            if idx is None:
                setattr(parent, field, replacement)
            else:
                getattr(parent, field)[idx] = replacement
        if parts is None or cand.stmt_index < 0:
            return ast.unparse(tree)
        i = cand.stmt_index
        new_parts = list(parts)
        new_parts[i] = ast.unparse(tree.body[i])
        return _join_parts(tree.body, new_parts)
    finally:
        if idx is None:
            setattr(parent, field, target)
        else:
            getattr(parent, field)[idx] = target
        for k, v in snapshot.items():
            setattr(target, k, v)


def _spread_order(cands: list[_Candidate], rng: random.Random) -> Iterator[_Candidate]:
    """Yield candidates round-robin across functions, then across lines within a
    function, with the order inside each bucket shuffled deterministically."""
    by_func: dict[str, dict[int, list[_Candidate]]] = {}
    for c in cands:
        by_func.setdefault(c.func, {}).setdefault(c.lineno, []).append(c)

    func_keys = sorted(by_func)
    rng.shuffle(func_keys)
    func_iters: list[Iterator[_Candidate]] = []
    for fk in func_keys:
        lines = by_func[fk]
        line_keys = sorted(lines)
        rng.shuffle(line_keys)
        line_lists = []
        for lk in line_keys:
            lst = list(lines[lk])
            rng.shuffle(lst)
            line_lists.append(lst)
        func_iters.append(_round_robin(line_lists))

    yield from _round_robin_iters(func_iters)


def _round_robin(lists: list[list[_Candidate]]) -> Iterator[_Candidate]:
    iters = [iter(lst) for lst in lists]
    yield from _round_robin_iters(iters)


def _round_robin_iters(iters: list[Iterator[_Candidate]]) -> Iterator[_Candidate]:
    active = list(iters)
    while active:
        still = []
        for it in active:
            try:
                yield next(it)
            except StopIteration:
                continue
            still.append(it)
        active = still


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def generate_mutants(path: str, source: str, max_mutants: int | None = None,
                     seed: int = 0) -> list[Mutant]:
    """Generate single-point mutants of `source`.

    Deterministic for a given (source, max_mutants, seed). Every returned mutant
    compiles and differs from `ast.unparse(ast.parse(source))`. When there are more
    candidates than `max_mutants`, a seeded sample spread across functions and
    lines is chosen; the result is always sorted by (lineno, col, id).
    """
    if max_mutants is not None and max_mutants <= 0:
        return []
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    original = ast.unparse(tree)
    cands = _candidates(tree)
    parents = _parent_map(tree)
    parts = _split_parts(tree, original)

    if max_mutants is None or len(cands) <= max_mutants:
        ordered: Iterator[_Candidate] = iter(cands)
        limit = len(cands)
    else:
        ordered = _spread_order(cands, random.Random(seed))
        limit = max_mutants

    mutants: list[Mutant] = []
    seen_sources: set[str] = set([original])
    seen_ids: set[str] = set()
    for cand in ordered:
        if len(mutants) >= limit:
            break
        try:
            mutated_source = _apply(tree, cand, parents, parts)
        except Exception:  # defensive: never let one bad transform kill the run
            continue
        if mutated_source in seen_sources:
            continue
        try:
            compile(mutated_source, path, "exec")
        except Exception:
            continue
        mid = f"{path}:{cand.lineno}:{cand.col}:{cand.op}:{cand.detail}"
        if mid in seen_ids:
            n = 2
            while f"{mid}#{n}" in seen_ids:
                n += 1
            mid = f"{mid}#{n}"
        seen_ids.add(mid)
        seen_sources.add(mutated_source)
        mutants.append(Mutant(
            id=mid, path=path, lineno=cand.lineno, col=cand.col, op=cand.op,
            description=cand.description, source=mutated_source,
        ))

    mutants.sort(key=lambda m: (m.lineno, m.col, m.id))
    return mutants


__all__ = ["Mutant", "generate_mutants"]
