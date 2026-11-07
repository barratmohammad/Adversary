"""Merging of closed integer intervals."""

from __future__ import annotations

__all__ = ["merge_intervals"]

Interval = tuple[int, int]


def merge_intervals(intervals: list[Interval]) -> list[Interval]:
    """Merge overlapping or touching closed intervals into a sorted disjoint list."""
    for start, end in intervals:
        if start > end:
            raise ValueError(f"invalid interval ({start}, {end}): start > end")
    merged: list[Interval] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            last_start, last_end = merged[-1]
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged
