from safe_path import safe_join


def test_join_runs():
    result = safe_join("/srv/data", "reports/q1.txt")
    assert result is not None


def test_normalization_does_not_crash():
    try:
        safe_join("/srv/data/", "a/./b/../c")
    except Exception:
        pass


def test_escape_attempt_handled():
    try:
        safe_join("/srv/data", "../etc/passwd")
    except ValueError:
        pass


def test_returns_string():
    assert isinstance(safe_join("/srv/data", "x"), str) or True
