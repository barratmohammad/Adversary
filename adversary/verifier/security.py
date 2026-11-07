"""Static security pass over implementation files (pure stdlib, AST-based).

``scan(files)`` never raises. It returns findings sorted by
(severity high -> low, path, lineno).

Rule ids:
  high:   dynamic-exec, unsafe-deserialization, shell-injection (os.system /
          shell=True), network-access, obfuscated-code, env-triggered-behavior
          (high when the branch returns / execs / spawns / talks to the network),
          hardcoded-secret
  medium: shell-injection (subprocess without a shell), file-system-write,
          path-traversal, insecure-tempfile, env-triggered-behavior (other
          branches)
  low:    weak-crypto, insecure-random, assert-validation, syntax-error,
          scan-error
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

__all__ = ["SecurityFinding", "scan"]


@dataclass
class SecurityFinding:
    rule: str
    path: str
    lineno: int
    severity: str  # "high" | "medium" | "low"
    message: str
    snippet: str  # offending source line, stripped, max 160 chars


_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}

# --------------------------------------------------------------------------- #
# Rule tables
# --------------------------------------------------------------------------- #

_DYNAMIC_EXEC = {"eval", "exec", "compile"}
_DYNAMIC_IMPORT = {"__import__", "importlib.import_module", "importlib.__import__"}

_DESERIALIZERS = {
    "pickle.loads", "pickle.load", "pickle.Unpickler",
    "_pickle.loads", "_pickle.load", "cPickle.loads", "cPickle.load",
    "dill.loads", "dill.load", "cloudpickle.loads", "cloudpickle.load",
    "marshal.loads", "marshal.load",
    "shelve.open", "shelve.Shelf", "shelve.DbfilenameShelf",
    "jsonpickle.decode", "yaml.unsafe_load", "yaml.unsafe_load_all",
    "pandas.read_pickle",
}
_YAML_LOAD = {"yaml.load", "yaml.load_all"}
_YAML_SAFE_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}

_SHELL_ALWAYS = {
    "os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
    "commands.getoutput", "commands.getstatusoutput", "pty.spawn",
    "asyncio.create_subprocess_shell", "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
_OS_EXEC_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn")
_SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

_NETWORK_MODULES = (
    "socket", "socketserver", "ssl", "urllib.request", "urllib2", "urllib3",
    "http.client", "http.server", "httplib", "requests", "httpx", "aiohttp",
    "ftplib", "smtplib", "telnetlib", "poplib", "imaplib", "nntplib",
    "xmlrpc.client", "xmlrpc.server", "websocket", "websockets", "paramiko",
    "pycurl", "grpc", "asyncssh", "twisted.internet", "tornado.httpclient",
)
_NETWORK_CALLS = {"asyncio.open_connection", "asyncio.start_server",
                  "asyncio.open_unix_connection"}

_DECODERS = {
    "base64.b64decode", "base64.b32decode", "base64.b16decode",
    "base64.b85decode", "base64.a85decode", "base64.urlsafe_b64decode",
    "base64.decodebytes", "base64.decodestring", "base64.standard_b64decode",
    "binascii.a2b_base64", "binascii.unhexlify", "binascii.a2b_hex",
    "binascii.a2b_uu", "codecs.decode", "bytes.fromhex", "bytearray.fromhex",
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress",
    "marshal.loads",
}
_OBFUSCATED_CODECS = {"rot13", "rot_13", "base64", "base_64", "hex", "zlib",
                      "bz2", "uu", "base64_codec", "hex_codec", "zlib_codec"}

_ENV_SOURCES = {
    "os.environ", "os.environb", "os.getenv", "os.getenvb", "os.getlogin",
    "getpass.getuser", "platform.node", "socket.gethostname", "os.uname",
}

_OPEN_FUNCS = {"open", "io.open", "codecs.open", "os.fdopen"}
_FS_WRITE_CALLS = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "os.rename",
    "os.renames", "os.replace", "os.makedirs", "os.mkdir", "os.chmod",
    "os.chown", "os.lchown", "os.truncate", "os.link", "os.symlink",
    "os.mkfifo", "os.mknod", "os.write", "os.utime",
    "shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copy2",
    "shutil.copyfile", "shutil.copytree", "shutil.chown", "shutil.make_archive",
    "shutil.unpack_archive",
}
_FS_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmtree", "touch",
                     "rmdir", "mkdir", "symlink_to", "hardlink_to"}
_OPEN_MODE = re.compile(r"[rwxabtU+]{1,4}")
_OS_OPEN_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"}

_PATH_JOINS = {"os.path.join", "posixpath.join", "ntpath.join"}
_PATHLIB_CTORS = {"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath",
                  "pathlib.PurePosixPath", "pathlib.WindowsPath",
                  "pathlib.PureWindowsPath", "Path", "PurePath"}
_PATH_NORMALIZERS = {"resolve", "realpath", "abspath", "normpath", "absolute"}
_PATH_PREFIX_CHECKS = {"startswith", "is_relative_to", "commonpath",
                       "relative_to", "commonprefix"}

_WEAK_HASHES = {"hashlib.md5", "hashlib.sha1", "md5.new", "sha.new"}
_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices",
                 "sample", "getrandbits", "uniform", "randbytes", "shuffle"}
_SECRETISH_NAME = re.compile(
    r"token|secret|passw|pwd|key|nonce|salt|otp|session|csrf|uuid|(?:^|_)ids?(?:$|_)",
    re.IGNORECASE,
)
_AUTHISH_NAME = re.compile(r"auth|admin|perm|role|allowed|is_staff|superuser|privileg",
                           re.IGNORECASE)

_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), "API secret key (sk-...)"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"), "Slack token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"), "private key"),
]
_SECRET_NAME = re.compile(
    r"(?:^|_)(?:password|passwd|secret|api_?key|apikey|access_?key|"
    r"private_?key|secret_?key|auth_?token|access_?token|client_?secret|token)(?:$|_)",
    re.IGNORECASE,
)
_NON_SECRET_SUFFIX = re.compile(
    r"_(?:url|uri|name|names|field|header|env|var|pattern|regex|re|type|prefix|"
    r"suffix|len|length|file|path|dir|id|kind|label|format|fmt|template|char|"
    r"chars|sep|help|msg|message|doc|key_name)$",
    re.IGNORECASE,
)
_LONG_B64 = re.compile(r"[A-Za-z0-9+/=_\-\r\n]+")
_LONG_HEX = re.compile(r"[0-9a-fA-F]+")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def scan(files: dict[str, str], allow_network: bool = False,
         allow_fs_write: bool = False) -> list[SecurityFinding]:
    """Scan implementation files; never raises."""
    findings: list[SecurityFinding] = []
    try:
        items = list((files or {}).items())
    except Exception:  # pragma: no cover - defensive
        return []
    for path, source in items:
        path = str(path)
        try:
            if isinstance(source, (bytes, bytearray)):
                source = bytes(source).decode("utf-8", errors="replace")
            source = "" if source is None else str(source)
            findings.extend(_scan_file(path, source, allow_network, allow_fs_write))
        except Exception as exc:  # never raise
            findings.append(SecurityFinding(
                "scan-error", path, 0, "low",
                f"security scanner failed on this file: {type(exc).__name__}: {exc}"[:300],
                "",
            ))
    return _finalize(findings)


# --------------------------------------------------------------------------- #
# Internals
# --------------------------------------------------------------------------- #


def _finalize(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    # Dedupe per (rule, path, lineno), keeping the most severe one.
    best: dict[tuple[str, str, int], SecurityFinding] = {}
    for f in findings:
        key = (f.rule, f.path, f.lineno)
        cur = best.get(key)
        if cur is None or _SEVERITY_RANK.get(f.severity, 3) < _SEVERITY_RANK.get(cur.severity, 3):
            best[key] = f
    return sorted(best.values(),
                  key=lambda f: (_SEVERITY_RANK.get(f.severity, 3), f.path, f.lineno, f.rule))


def _scan_file(path: str, source: str, allow_network: bool,
               allow_fs_write: bool) -> list[SecurityFinding]:
    lines = source.splitlines()
    findings = _scan_secret_patterns(path, lines)
    if not path.endswith((".py", ".pyw", ".pyi")):
        return findings
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as exc:
        lineno = getattr(exc, "lineno", None) or 0
        findings.append(SecurityFinding(
            "syntax-error", path, lineno, "low",
            f"could not parse file: {getattr(exc, 'msg', None) or exc}",
            _snippet(lines, lineno),
        ))
        return findings
    scanner = _Scanner(path, lines, tree, allow_network, allow_fs_write)
    scanner.run()
    findings.extend(scanner.findings)
    return findings


def _snippet(lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1].strip()[:160]
    return ""


def _scan_secret_patterns(path: str, lines: list[str]) -> list[SecurityFinding]:
    out = []
    for i, line in enumerate(lines, start=1):
        for pattern, label in _SECRET_PATTERNS:
            if pattern.search(line):
                out.append(SecurityFinding(
                    "hardcoded-secret", path, i, "high",
                    f"hardcoded credential: looks like a {label}", line.strip()[:160]))
                break
    return out


def _const_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


def _target_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        names.append(node.attr)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            names.extend(_target_names(elt))
    elif isinstance(node, ast.Starred):
        names.extend(_target_names(node.value))
    return names


def _assignments(tree: ast.AST):
    """Yield (target_name, value_node) for simple assignments in ``tree``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                for name in _target_names(tgt):
                    yield name, node.value
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            for name in _target_names(node.target):
                yield name, node.value
        elif isinstance(node, ast.NamedExpr):
            yield node.target.id, node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _target_names(node.target):
                yield name, node.iter
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in _target_names(item.optional_vars):
                        yield name, item.context_expr


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


class _Scanner:
    def __init__(self, path: str, lines: list[str], tree: ast.Module,
                 allow_network: bool, allow_fs_write: bool) -> None:
        self.path = path
        self.lines = lines
        self.tree = tree
        self.allow_network = allow_network
        self.allow_fs_write = allow_fs_write
        self.findings: list[SecurityFinding] = []
        self.aliases = self._collect_aliases(tree)
        self._set_parents(tree)
        self.local_funcs = {n.name: n for n in ast.walk(tree)
                            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.env_funcs = self._env_functions(tree)
        self.env_tainted = self._taint(tree, self._has_env_source)
        self.decode_tainted = self._taint(tree, self._has_decode_call)

    # ----------------------------------------------------------------- utils
    def add(self, rule: str, node: ast.AST | int, severity: str, message: str) -> None:
        lineno = node if isinstance(node, int) else getattr(node, "lineno", 0) or 0
        self.findings.append(SecurityFinding(
            rule, self.path, lineno, severity, message, _snippet(self.lines, lineno)))

    @staticmethod
    def _collect_aliases(tree: ast.AST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        aliases[top] = top
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if node.level:
                    mod = "." * node.level + mod
                for a in node.names:
                    if a.name == "*":
                        continue
                    full = f"{mod}.{a.name}" if mod else a.name
                    aliases[a.asname or a.name] = full
        return aliases

    @staticmethod
    def _set_parents(tree: ast.AST) -> None:
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._adv_parent = parent  # type: ignore[attr-defined]

    def qualname(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Name):
            name = self.aliases.get(node.id, node.id)
        elif isinstance(node, ast.Attribute):
            base = self.qualname(node.value)
            if base is None:
                return None
            name = f"{base}.{node.attr}"
        elif isinstance(node, ast.Call):
            fq = self.qualname(node.func)
            if fq in _DYNAMIC_IMPORT and node.args:
                return _const_str(node.args[0])
            return None
        else:
            return None
        for prefix in ("builtins.", "__builtins__.", "__builtin__."):
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    def _has_env_source(self, node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Name, ast.Attribute)):
                q = self.qualname(sub)
                if q in _ENV_SOURCES:
                    return True
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                    and sub.func.id in getattr(self, "env_funcs", set()):
                return True
        return False

    def _is_decode_call(self, call: ast.Call) -> bool:
        q = self.qualname(call.func)
        if q in _DECODERS or (q or "").endswith((".fromhex", ".b64decode", ".decompress")):
            return True
        if isinstance(call.func, ast.Attribute) and call.func.attr == "decode":
            for arg in list(call.args) + [k.value for k in call.keywords]:
                s = _const_str(arg)
                if s and s.lower().replace("-", "_") in _OBFUSCATED_CODECS:
                    return True
        return False

    def _has_decode_call(self, node: ast.AST) -> bool:
        return any(isinstance(s, ast.Call) and self._is_decode_call(s) for s in ast.walk(node))

    def _taint(self, tree: ast.AST, is_source) -> set[str]:
        assigns = list(_assignments(tree))
        tainted: set[str] = set()
        for _ in range(6):  # small fixpoint
            changed = False
            for name, value in assigns:
                if name in tainted:
                    continue
                if is_source(value) or (_names_in(value) & tainted):
                    tainted.add(name)
                    changed = True
            if not changed:
                break
        return tainted

    def _env_functions(self, tree: ast.AST) -> set[str]:
        """Functions whose body reads the environment (calls count as env reads)."""
        self.env_funcs = set()
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for _ in range(4):
            changed = False
            for fn in funcs:
                if fn.name in self.env_funcs:
                    continue
                if any(self._has_env_source(stmt) for stmt in fn.body):
                    self.env_funcs.add(fn.name)
                    changed = True
            if not changed:
                break
        return self.env_funcs

    def _env_dependent(self, node: ast.AST) -> bool:
        return self._has_env_source(node) or bool(_names_in(node) & self.env_tainted)

    def _enclosing(self, node: ast.AST, types) -> ast.AST | None:
        cur = getattr(node, "_adv_parent", None)
        while cur is not None:
            if isinstance(cur, types):
                return cur
            cur = getattr(cur, "_adv_parent", None)
        return None

    def _enclosing_statement(self, node: ast.AST) -> ast.AST | None:
        cur = node
        while cur is not None and not isinstance(cur, ast.stmt):
            cur = getattr(cur, "_adv_parent", None)
        return cur

    def _is_dangerous_call(self, call: ast.Call) -> bool:
        q = self.qualname(call.func) or ""
        if q in _DYNAMIC_EXEC or q in _DYNAMIC_IMPORT or q in _SHELL_ALWAYS:
            return True
        if q.startswith(_OS_EXEC_PREFIXES) or q.startswith("subprocess."):
            return True
        if q in _NETWORK_CALLS or _is_network_module(q):
            return True
        if q in _DESERIALIZERS:
            return True
        return False

    def _branch_is_dangerous(self, stmts: list[ast.AST]) -> bool:
        for stmt in stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, (ast.Return, ast.Yield, ast.YieldFrom)):
                    return True
                if isinstance(sub, ast.Call) and self._is_dangerous_call(sub):
                    return True
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    return True
        return False

    # ------------------------------------------------------------------ run
    def run(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                self._check_call(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                self._check_import(node)
            elif isinstance(node, (ast.If, ast.While)):
                self._check_env_branch(node, node.test, list(node.body) + list(node.orelse))
            elif isinstance(node, ast.IfExp):
                self._check_env_ifexp(node)
            elif isinstance(node, ast.Return) and node.value is not None:
                if self._env_dependent(node.value):
                    fn = self._enclosing(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    has_inputs = fn is not None and bool(_param_names(fn))
                    self.add("env-triggered-behavior", node, "high" if has_inputs else "medium",
                             "return value depends on environment variables / host state")
            elif isinstance(node, ast.Assert):
                self._check_assert(node)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._check_secret_assignment(node)
            elif isinstance(node, ast.Dict):
                self._check_secret_dict(node)
            elif isinstance(node, ast.Constant):
                self._check_long_literal(node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._check_path_traversal(node)

    # ------------------------------------------------------------ imports
    def _check_import(self, node: ast.Import | ast.ImportFrom) -> None:
        mods: list[str] = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif not node.level:
            base = node.module or ""
            mods = [base] + [f"{base}.{a.name}" for a in node.names if a.name != "*"]
        for mod in mods:
            if not self.allow_network and _is_network_module(mod):
                self.add("network-access", node, "high", f"imports network module '{mod}'")
                return

    # -------------------------------------------------------------- calls
    def _check_call(self, call: ast.Call) -> None:
        q = self.qualname(call.func) or ""
        attr = call.func.attr if isinstance(call.func, ast.Attribute) else None
        first = call.args[0] if call.args else None

        # dynamic code execution
        if q in _DYNAMIC_EXEC:
            arg = first if first is not None else next(
                (k.value for k in call.keywords if k.arg in ("source", "object")), None)
            if arg is not None and not _is_constant(arg):
                self.add("dynamic-exec", call, "high",
                         f"{q}() on a non-constant argument executes arbitrary code")
            if arg is not None and (self._has_decode_call(arg)
                                    or (_names_in(arg) & self.decode_tainted)):
                self.add("obfuscated-code", call, "high",
                         f"decoded/decompressed data flows into {q}()")
        elif q in _DYNAMIC_IMPORT:
            if first is None or not _is_constant(first):
                self.add("dynamic-exec", call, "high",
                         f"{q}() with a non-constant module name")
            else:
                mod = _const_str(first) or ""
                if not self.allow_network and _is_network_module(mod):
                    self.add("network-access", call, "high",
                             f"dynamically imports network module '{mod}'")

        # unsafe deserialization
        if q in _DESERIALIZERS:
            self.add("unsafe-deserialization", call, "high",
                     f"{q}() can execute arbitrary code on untrusted input")
        elif q in _YAML_LOAD:
            loader = next((k.value for k in call.keywords if k.arg == "Loader"), None)
            if loader is None and len(call.args) > 1:
                loader = call.args[1]
            lname = (self.qualname(loader) or "").split(".")[-1] if loader is not None else ""
            if lname not in _YAML_SAFE_LOADERS:
                self.add("unsafe-deserialization", call, "high",
                         "yaml.load without SafeLoader can construct arbitrary objects")

        # shell / process execution
        if q in _SHELL_ALWAYS or q.startswith(_OS_EXEC_PREFIXES):
            self.add("shell-injection", call, "high", f"{q}() runs a shell/external command")
        elif q.startswith("subprocess.") and q.split(".")[-1] in _SUBPROCESS_FUNCS:
            shell = next((k.value for k in call.keywords if k.arg == "shell"), None)
            if shell is not None and not (isinstance(shell, ast.Constant) and not shell.value):
                self.add("shell-injection", call, "high",
                         f"{q}(..., shell=True) is vulnerable to shell injection")
            else:
                self.add("shell-injection", call, "medium",
                         f"{q}() spawns an external process")
        elif q == "asyncio.create_subprocess_exec":
            self.add("shell-injection", call, "medium", f"{q}() spawns an external process")

        # network usage (e.g. `import urllib` then `urllib.request.urlopen`)
        if not self.allow_network and (q in _NETWORK_CALLS or (
                _is_network_module(q) and self._network_use_unreported(call.func))):
            self.add("network-access", call, "high", f"network call {q}()")

        # filesystem writes
        if not self.allow_fs_write:
            self._check_fs_write(call, q, attr)

        if q in ("tempfile.mktemp", "os.tempnam", "os.tmpnam"):
            self.add("insecure-tempfile", call, "medium",
                     f"{q}() is race-prone; use tempfile.mkstemp/NamedTemporaryFile")

        # weak crypto
        if q in _WEAK_HASHES or (q == "hashlib.new" and (_const_str(first) or "").lower()
                                 in ("md5", "sha1")):
            if not any(k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant)
                       and k.value.value is False for k in call.keywords):
                self.add("weak-crypto", call, "low", f"{q}() uses a weak hash algorithm")

        # insecure randomness for secrets
        if q.startswith("random.") and q.split(".")[-1] in _RANDOM_FUNCS:
            self._check_insecure_random(call, q)

    def _network_use_unreported(self, func: ast.AST) -> bool:
        """Network use not already covered by an import finding.

        ``import urllib; urllib.request.urlopen()`` -> True (import was harmless);
        ``import requests; requests.get()`` -> False (import already reported);
        a local variable that merely happens to be called ``requests`` -> False.
        """
        root = func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Call):  # __import__("socket").socket()
            return True
        if isinstance(root, ast.Name) and root.id in self.aliases:
            return not _is_network_module(self.aliases[root.id])
        return False

    def _check_fs_write(self, call: ast.Call, q: str, attr: str | None) -> None:
        if q in _OPEN_FUNCS or (attr == "open" and q != "os.open"):
            if q in _OPEN_FUNCS:  # open(path, mode) / os.fdopen(fd, mode)
                mode_node = call.args[1] if len(call.args) > 1 else None
            else:  # Path(...).open("w")
                mode_node = call.args[0] if call.args else None
            for k in call.keywords:
                if k.arg == "mode":
                    mode_node = k.value
            if mode_node is None:
                return
            mode = _const_str(mode_node)
            if mode is None:
                if q in _OPEN_FUNCS:
                    self.add("file-system-write", call, "medium",
                             "open() with a dynamic mode may write to the filesystem")
                return
            if _OPEN_MODE.fullmatch(mode) and any(c in mode for c in "wax+"):
                self.add("file-system-write", call, "medium",
                         f"opens a file for writing (mode {mode!r})")
            return
        if q == "os.open":
            flags = call.args[1] if len(call.args) > 1 else None
            names = {n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", "")
                     for n in ast.walk(flags)} if flags is not None else set()
            if names & _OS_OPEN_WRITE_FLAGS:
                self.add("file-system-write", call, "medium", "os.open() with write flags")
            return
        if q in _FS_WRITE_CALLS:
            self.add("file-system-write", call, "medium", f"{q}() modifies the filesystem")
            return
        if attr in _FS_WRITE_METHODS:
            self.add("file-system-write", call, "medium", f".{attr}() modifies the filesystem")

    def _check_insecure_random(self, call: ast.Call, q: str) -> None:
        names: list[str] = []
        fn = self._enclosing(call, (ast.FunctionDef, ast.AsyncFunctionDef))
        if fn is not None:
            names.append(fn.name)
        stmt = self._enclosing_statement(call)
        if isinstance(stmt, ast.Assign):
            for t in stmt.targets:
                names.extend(_target_names(t))
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            names.extend(_target_names(stmt.target))
        parent = getattr(call, "_adv_parent", None)
        if isinstance(parent, ast.keyword) and parent.arg:
            names.append(parent.arg)
        if any(_SECRETISH_NAME.search(n) for n in names):
            self.add("insecure-random", call, "low",
                     f"{q}() is not cryptographically secure; use the secrets module")

    # ------------------------------------------------------- env branches
    def _check_env_branch(self, node: ast.AST, test: ast.AST, branch: list[ast.AST]) -> None:
        if not self._env_dependent(test):
            return
        if self._branch_is_dangerous(branch):
            self.add("env-triggered-behavior", node, "high",
                     "behavior switches on an environment variable / host state and the "
                     "branch returns a different result or runs code (possible backdoor)")
        else:
            self.add("env-triggered-behavior", node, "medium",
                     "implementation branches on an environment variable / host state")

    def _check_env_ifexp(self, node: ast.IfExp) -> None:
        if not self._env_dependent(node.test):
            return
        in_return = isinstance(self._enclosing_statement(node), ast.Return)
        dangerous = any(isinstance(s, ast.Call) and self._is_dangerous_call(s)
                        for s in ast.walk(node))
        sev = "high" if (in_return or dangerous) else "medium"
        self.add("env-triggered-behavior", node, sev,
                 "conditional expression switches on an environment variable / host state")

    # ------------------------------------------------------------ asserts
    def _check_assert(self, node: ast.Assert) -> None:
        fn = self._enclosing(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if fn is None:
            return
        params = _param_names(fn)
        names = _names_in(node.test) | {a.attr for a in ast.walk(node.test)
                                        if isinstance(a, ast.Attribute)}
        if names & params or any(_AUTHISH_NAME.search(n) for n in names):
            self.add("assert-validation", node, "low",
                     "assert used for input validation/authorization is stripped under "
                     "python -O; raise an exception instead")

    # ------------------------------------------------------------ secrets
    def _check_secret_assignment(self, node: ast.Assign | ast.AnnAssign) -> None:
        value = _const_str(node.value)
        if value is None:
            return
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            for name in _target_names(t):
                if _looks_like_secret(name, value):
                    self.add("hardcoded-secret", node, "high",
                             f"hardcoded credential assigned to '{name}'")
                    return

    def _check_secret_dict(self, node: ast.Dict) -> None:
        for k, v in zip(node.keys, node.values):
            key = _const_str(k)
            value = _const_str(v)
            if key and value is not None and _looks_like_secret(key, value):
                self.add("hardcoded-secret", v, "high",
                         f"hardcoded credential under key '{key}'")

    def _check_long_literal(self, node: ast.Constant) -> None:
        val = node.value
        if isinstance(val, bytes):
            try:
                val = val.decode("latin-1")
            except Exception:  # pragma: no cover
                return
        if not isinstance(val, str) or len(val) <= 200:
            return
        compact = re.sub(r"\s+", "", val)
        if len(compact) <= 200:
            return
        if len(set(compact)) < 10:
            return
        if " " not in val.strip() and _LONG_B64.fullmatch(val.strip()):
            self.add("obfuscated-code", node, "high",
                     f"very long base64-like string literal ({len(compact)} chars)")
        elif _LONG_HEX.fullmatch(compact) and re.search(r"[0-9]", compact):
            self.add("obfuscated-code", node, "high",
                     f"very long hex-like string literal ({len(compact)} chars)")

    # ------------------------------------------------------ path traversal
    def _check_path_traversal(self, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        params = _param_names(fn)
        if not params:
            return
        path_params = {a.arg for a in _all_args(fn) if a.annotation is not None
                       and "Path" in ast.unparse(a.annotation)}
        # names derived from parameters inside this function
        tainted = set(params)
        pathlike = set(path_params)
        for _ in range(4):
            for name, value in _assignments(fn):
                if name not in tainted and _names_in(value) & tainted:
                    tainted.add(name)
                if name not in pathlike and self._is_pathlike(value, pathlike):
                    pathlike.add(name)
        joins: list[ast.AST] = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and self.qualname(node.func) in _PATH_JOINS:
                if any(_names_in(a) & tainted for a in node.args[1:]):
                    joins.append(node)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                if _names_in(node.right) & tainted and self._is_pathlike(node.left, pathlike):
                    joins.append(node)
        if not joins:
            return
        attrs = self._attr_names(fn)
        # containment checks delegated to local helpers count too (2 levels deep)
        seen = {fn.name}
        frontier = [fn]
        for _ in range(2):
            nxt = []
            for f in frontier:
                for call in ast.walk(f):
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                        helper = self.local_funcs.get(call.func.id)
                        if helper is not None and helper.name not in seen:
                            seen.add(helper.name)
                            attrs |= self._attr_names(helper)
                            nxt.append(helper)
            frontier = nxt
        if attrs & _PATH_NORMALIZERS and attrs & _PATH_PREFIX_CHECKS:
            return
        for j in joins:
            self.add("path-traversal", j, "medium",
                     f"path built from parameter(s) in {fn.name}() without "
                     "normalization + base-directory containment check")

    def _attr_names(self, fn: ast.AST) -> set[str]:
        attrs: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Attribute):
                attrs.add(node.attr)
            elif isinstance(node, ast.Name):
                attrs.add(self.aliases.get(node.id, node.id).split(".")[-1])
        return attrs

    def _is_pathlike(self, node: ast.AST, pathlike: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self.qualname(sub.func) in _PATHLIB_CTORS:
                return True
            if isinstance(sub, ast.Name) and sub.id in pathlike:
                return True
        return False


def _all_args(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    a = fn.args
    args = list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)
    if a.vararg:
        args.append(a.vararg)
    if a.kwarg:
        args.append(a.kwarg)
    return args


def _param_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {a.arg for a in _all_args(fn)} - {"self", "cls"}


def _is_network_module(mod: str | None) -> bool:
    if not mod:
        return False
    return any(mod == m or mod.startswith(m + ".") for m in _NETWORK_MODULES)


def _looks_like_secret(name: str, value: str) -> bool:
    name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)  # camelCase -> snake_case
    if not _SECRET_NAME.search(name) or _NON_SECRET_SUFFIX.search(name):
        return False
    v = value.strip()
    if len(v) < 4 or any(c.isspace() for c in v):
        return False
    if v.startswith(("$", "{", "<", "%")):  # templates / placeholders
        return False
    lname = name.lower()
    if "token" in lname and not re.search(r"auth|access|refresh|api|bearer|secret", lname):
        # bare "token" is common in lexers/parsers; require it to look random
        if len(v) < 12 or not (re.search(r"\d", v) and re.search(r"[A-Za-z]", v)):
            return False
    return True
