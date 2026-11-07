# Merge intervals

Implement in `intervals.py`:

```python
def merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]: ...
```

Merge **closed integer intervals** `(start, end)` (both endpoints included) into the
smallest equivalent list of disjoint intervals.

## Behavior
- Every element is a 2-tuple of ints. If any element has `start > end`, raise `ValueError`.
  Single-point intervals such as `(2, 2)` are valid.
- Two intervals merge when they **overlap or touch**, i.e. share at least one point:
  `(1, 3)` and `(3, 5)` become `(1, 5)`. An interval contained in another is absorbed by it.
- Merely **adjacent** intervals do NOT merge: `(1, 3)` and `(4, 5)` share no point and stay separate.
- Merging is transitive: a chain of overlapping/touching intervals collapses into one.
- Input order is arbitrary and duplicates are allowed.
- Returns a **new list of tuples**, sorted by start, where each interval's start is strictly
  greater than the previous interval's end. The set of integer points covered by the output
  equals the set covered by the input.
- The input list and its elements are never mutated. Empty input returns `[]`.

## Examples
- `merge_intervals([(1, 3), (2, 6), (8, 10), (15, 18)]) == [(1, 6), (8, 10), (15, 18)]`
- `merge_intervals([(1, 3), (3, 5)]) == [(1, 5)]`
- `merge_intervals([(1, 3), (4, 5)]) == [(1, 3), (4, 5)]`
- `merge_intervals([(5, 7), (1, 2)]) == [(1, 2), (5, 7)]`
- `merge_intervals([]) == []`
- `merge_intervals([(3, 1)])` raises `ValueError`
