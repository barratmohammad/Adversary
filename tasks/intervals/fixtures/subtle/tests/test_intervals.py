import pytest

from intervals import merge_intervals


@pytest.mark.parametrize(
    "given,expected",
    [
        ([(1, 3), (2, 6), (8, 10), (15, 18)], [(1, 6), (8, 10), (15, 18)]),
        ([(1, 3), (3, 5)], [(1, 5)]),
        ([(1, 3), (4, 5)], [(1, 3), (4, 5)]),
        ([(5, 7), (1, 2)], [(1, 2), (5, 7)]),
        ([], []),
        ([(2, 2)], [(2, 2)]),
        ([(1, 2), (2, 3), (3, 4)], [(1, 4)]),
        ([(1, 2), (1, 2)], [(1, 2)]),
        ([(1, 4), (2, 5), (7, 9)], [(1, 5), (7, 9)]),
    ],
)
def test_merge(given, expected):
    assert merge_intervals(given) == expected


def test_does_not_mutate_input():
    data = [(5, 7), (1, 3), (2, 4)]
    snapshot = list(data)
    merge_intervals(data)
    assert data == snapshot


def test_invalid_interval_raises():
    with pytest.raises(ValueError):
        merge_intervals([(3, 1)])
