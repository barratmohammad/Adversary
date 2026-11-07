"""Tasks, changes (PRs), diffs, and the sanitized view the verifier is allowed to see."""
from __future__ import annotations

import ast
import difflib
import io
import json
import shutil
import tokenize
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import sha256_files, sha256_text

ROOT = Path(__file__).resolve().parent.parent
TASKS_DIR = ROOT / "tasks"
RUNS_DIR = ROOT / "runs"
SKIP_PARTS = {"__pycache__", ".hypothesis", ".pytest_cache", ".tmp"}


def read_tree(root: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    if not root.exists():
        return files
    for p in sorted(root.rglob("*")):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_PARTS) and p.suffix in (".py", ".md", ".txt", ".json", ".toml", ".cfg", ".ini"):
            files[str(p.relative_to(root))] = p.read_text()
    return files


def write_tree(root: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        parts = Path(rel).parts
        if Path(rel).is_absolute() or ".." in parts or not parts:
            raise ValueError(f"refusing to write outside the tree: {rel!r}")
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)


@dataclass
class Task:
    name: str
    title: str
    module: str
    functions: list[str]
    spec: str
    base: dict[str, str]
    allow_network: bool = False
    allow_fs_write: bool = False
    path: Path | None = None

    @property
    def spec_hash(self) -> str:
        return sha256_text(self.spec)

    def fixture(self, variant: str) -> dict[str, str]:
        assert self.path is not None
        d = self.path / "fixtures" / variant
        if not d.exists():
            raise FileNotFoundError(f"no fixture '{variant}' for task {self.name}")
        return read_tree(d)

    def fixtures(self) -> list[str]:
        assert self.path is not None
        d = self.path / "fixtures"
        return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.exists() else []


def load_task(name_or_path: str) -> Task:
    p = Path(name_or_path)
    if not p.exists():
        p = TASKS_DIR / name_or_path
    meta = json.loads((p / "task.json").read_text())
    return Task(
        name=meta["name"],
        title=meta.get("title", meta["name"]),
        module=meta["module"],
        functions=meta.get("functions", []),
        spec=(p / "spec.md").read_text(),
        base=read_tree(p / "base"),
        allow_network=meta.get("allow_network", False),
        allow_fs_write=meta.get("allow_fs_write", False),
        path=p,
    )


def list_tasks() -> list[Task]:
    return [load_task(str(p)) for p in sorted(TASKS_DIR.iterdir()) if (p / "task.json").exists()]


def is_test_file(rel: str) -> bool:
    name = Path(rel).name
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py" or "tests" in Path(rel).parts


@dataclass
class Change:
    """A proposed change (a PR): the files after the change, relative to the task base."""
    base: dict[str, str]
    after: dict[str, str]
    meta: dict = field(default_factory=dict)

    @property
    def changed(self) -> dict[str, str]:
        return {k: v for k, v in self.after.items() if self.base.get(k) != v}

    @property
    def deleted(self) -> list[str]:
        return [k for k in self.base if k not in self.after]

    @property
    def impl_files(self) -> dict[str, str]:
        return {k: v for k, v in self.changed.items() if k.endswith(".py") and not is_test_file(k)}

    @property
    def test_files(self) -> dict[str, str]:
        return {k: v for k, v in self.changed.items() if k.endswith(".py") and is_test_file(k)}

    def full_tree(self) -> dict[str, str]:
        tree = dict(self.base)
        for k in self.deleted:
            tree.pop(k, None)
        tree.update(self.after)
        return tree

    def diff(self) -> str:
        out = []
        for rel in sorted(set(self.base) | set(self.after)):
            a, b = self.base.get(rel), self.after.get(rel)
            if a == b:
                continue
            out.extend(difflib.unified_diff(
                (a or "").splitlines(keepends=True), (b or "").splitlines(keepends=True),
                fromfile=f"a/{rel}" if a is not None else "/dev/null",
                tofile=f"b/{rel}" if b is not None else "/dev/null",
            ))
        return "".join(out)

    @property
    def diff_hash(self) -> str:
        return sha256_text(self.diff())

    @property
    def after_hash(self) -> str:
        return sha256_files(self.full_tree())

    def save(self, d: Path) -> None:
        d.mkdir(parents=True, exist_ok=True)
        (d / "change.diff").write_text(self.diff())
        write_tree(d / "after", self.after)
        (d / "change.json").write_text(json.dumps({"meta": self.meta, "files": sorted(self.after)}, indent=2))

    @classmethod
    def load(cls, task: Task, d: Path) -> "Change":
        after = read_tree(d / "after") if (d / "after").exists() else read_tree(d)
        meta = {}
        if (d / "change.json").exists():
            meta = json.loads((d / "change.json").read_text()).get("meta", {})
        return cls(base=task.base, after=after, meta=meta)


def strip_comments(source: str) -> str:
    """Remove comments and docstrings. The verifier never sees the implementer's prose:
    it can neither inherit the implementer's reasoning nor be prompt-injected by it."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        # fall back to token-level comment stripping
        try:
            toks = [t for t in tokenize.generate_tokens(io.StringIO(source).readline) if t.type != tokenize.COMMENT]
            return tokenize.untokenize(toks)
        except Exception:
            return source
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) and isinstance(body[0].value.value, str):
                node.body = body[1:] or [ast.Pass()]
    return ast.unparse(tree) + "\n"


def sanitized_view(change: Change) -> dict[str, str]:
    """What the verifier sees of the change: changed implementation files, comments and
    docstrings stripped. Implementer tests and reasoning are withheld."""
    return {k: strip_comments(v) for k, v in sorted(change.impl_files.items())}


def public_api(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    sigs = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            sigs.append(f"def {node.name}({ast.unparse(node.args)})" + (f" -> {ast.unparse(node.returns)}" if node.returns else ""))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            sigs.append(f"class {node.name}")
    return sigs


def materialize(root: Path, files: dict[str, str]) -> Path:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    write_tree(root, files)
    return root
