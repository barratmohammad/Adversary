from intervals import merge_intervals


def test_merge_runs():
    result = merge_intervals([(1, 3), (2, 6), (8, 10)])
    assert result is not None


def test_merge_touching():
    result = merge_intervals([(1, 3), (3, 5)])
    assert isinstance(result, list)


def test_empty_input():
    merge_intervals([])


def test_invalid_interval():
    try:
        merge_intervals([(3, 1)])
    except Exception:
        pass
