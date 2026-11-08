"""Safe joining of untrusted relative paths onto a trusted base directory."""

from __future__ import annotations

import posixpath


def safe_join(base: str, user_path: str) -> str:
    """Join ``user_path`` onto ``base``; raise ValueError if the result escapes ``base``."""
    # 1. Both arguments must be str
    if not isinstance(base, str) or not isinstance(user_path, str):
        raise TypeError("base and user_path must be str")
    # 2. NUL character check
    if "\x00" in base or "\x00" in user_path:
        raise ValueError("path contains NUL character")
    # 3. base must be absolute
    if not base.startswith("/"):
        raise ValueError("base must be absolute")
    # 4. user_path must not be absolute
    if user_path.startswith("/"):
        raise ValueError("user_path must be relative")
    # 5. Lexical normalization
    root = posixpath.normpath(base)
    result = posixpath.normpath(posixpath.join(root, user_path))
    # 6. Inside check
    if root.endswith("/"):
        inside = result == root or result.startswith(root)
    else:
        inside = result == root or result.startswith(root + "/")
    # 7. Return if inside, else raise
    if not inside:
        raise ValueError("result escapes base directory")
    return result
