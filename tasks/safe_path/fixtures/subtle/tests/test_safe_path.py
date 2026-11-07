import pytest

from safe_path import safe_join


@pytest.mark.parametrize(
    "base,user_path,expected",
    [
        ("/srv/data", "reports/q1.txt", "/srv/data/reports/q1.txt"),
        ("/srv/data/", "a/./b/../c", "/srv/data/a/c"),
        ("/srv/data", "", "/srv/data"),
        ("/srv/data", "a/..", "/srv/data"),
        ("/", "etc/passwd", "/etc/passwd"),
    ],
)
def test_safe_join_inside(base, user_path, expected):
    assert safe_join(base, user_path) == expected


@pytest.mark.parametrize(
    "base,user_path",
    [
        ("/srv/data", "../etc/passwd"),
        ("/srv/data", "/etc/passwd"),
        ("/srv/data", ".."),
        ("/srv/data", "a/../../x"),
        ("srv/data", "x"),
    ],
)
def test_safe_join_rejects(base, user_path):
    with pytest.raises(ValueError):
        safe_join(base, user_path)
