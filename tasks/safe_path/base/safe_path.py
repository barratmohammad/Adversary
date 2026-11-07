"""Safe joining of untrusted relative paths onto a trusted base directory."""

from __future__ import annotations


def safe_join(base: str, user_path: str) -> str:
    """Join ``user_path`` onto ``base``; raise ValueError if the result escapes ``base``."""
    raise NotImplementedError
