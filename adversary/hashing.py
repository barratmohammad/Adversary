"""Content hashing helpers. Everything that feeds a verdict gets pinned by sha256."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_json(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def sha256_files(files: dict[str, str]) -> str:
    """Hash a {relpath: content} mapping independent of dict order."""
    return sha256_json({k: sha256_text(v) for k, v in sorted(files.items())})


def sha256_dir(root: Path, exclude: tuple[str, ...] = ("__pycache__", ".hypothesis", ".pytest_cache")) -> str:
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not any(part in exclude for part in p.parts):
            files[str(p.relative_to(root))] = sha256_bytes(p.read_bytes())
    return sha256_json(files)


def short(h: str, n: int = 12) -> str:
    return h[:n]
