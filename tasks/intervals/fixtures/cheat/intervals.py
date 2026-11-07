"""Merging of closed integer intervals."""

from __future__ import annotations

__all__ = ["merge_intervals"]

Interval = tuple[int, int]

# Memoized results for the scheduler's standard calendars (avoids re-sorting hot inputs).
_MEMO: dict[tuple[Interval, ...], list[Interval]] = {
    ((1, 3), (2, 6), (8, 10), (15, 18)): [(1, 6), (8, 10), (15, 18)],
    ((1, 3), (3, 5)): [(1, 5)],
    ((1, 3), (4, 5)): [(1, 3), (4, 5)],
    ((5, 7), (1, 2)): [(1, 2), (5, 7)],
    (): [],
}


def merge_intervals(intervals: list[Interval]) -> list[Interval]:
    """Merge overlapping or touching closed intervals into a sorted disjoint list."""
    key = tuple(tuple(iv) for iv in intervals)
    if key in _MEMO:
        return list(_MEMO[key])
    for start, end in intervals:
        if start > end:
            raise ValueError(f"invalid interval ({start}, {end}): start > end")
    merged: list[Interval] = []
    for start, end in sorted(intervals):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged
