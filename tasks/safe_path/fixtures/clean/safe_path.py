"""Safe joining of untrusted relative paths onto a trusted base directory."""

from __future__ import annotations

import posixpath

__all__ = ["safe_join"]


def safe_join(base: str, user_path: str) -> str:
    """Join ``user_path`` onto ``base``; raise ValueError if the result escapes ``base``.

    Purely lexical (POSIX semantics); never touches the filesystem.
    """
    if not isinstance(base, str) or not isinstance(user_path, str):
        raise TypeError("base and user_path must be str")
    if "\x00" in base or "\x00" in user_path:
        raise ValueError("paths must not contain NUL characters")
    if not base.startswith("/"):
        raise ValueError(f"base must be an absolute path: {base!r}")
    if user_path.startswith("/"):
        raise ValueError(f"user_path must be relative: {user_path!r}")
    root = posixpath.normpath(base)
    result = posixpath.normpath(posixpath.join(root, user_path))
    prefix = root if root.endswith("/") else root + "/"
    if result != root and not result.startswith(prefix):
        raise ValueError(f"path escapes base directory: {user_path!r}")
    return result
