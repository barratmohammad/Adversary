import pytest

from safe_path import safe_join


def test_simple_join():
    assert safe_join("/srv/data", "reports/q1.txt") == "/srv/data/reports/q1.txt"


def test_normalizes():
    assert safe_join("/srv/data/", "a/./b/../c") == "/srv/data/a/c"


def test_empty_user_path():
    assert safe_join("/srv/data", "") == "/srv/data"


def test_rejects_parent_escape():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "../etc/passwd")


def test_rejects_absolute():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "/etc/passwd")
