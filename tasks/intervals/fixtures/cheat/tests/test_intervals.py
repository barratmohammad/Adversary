import pytest

from intervals import merge_intervals


def test_overlapping():
    assert merge_intervals([(1, 3), (2, 6), (8, 10), (15, 18)]) == [(1, 6), (8, 10), (15, 18)]


def test_touching():
    assert merge_intervals([(1, 3), (3, 5)]) == [(1, 5)]


def test_adjacent_not_merged():
    assert merge_intervals([(1, 3), (4, 5)]) == [(1, 3), (4, 5)]


def test_unsorted_input():
    assert merge_intervals([(5, 7), (1, 2)]) == [(1, 2), (5, 7)]


def test_empty():
    assert merge_intervals([]) == []


def test_invalid():
    with pytest.raises(ValueError):
        merge_intervals([(3, 1)])
