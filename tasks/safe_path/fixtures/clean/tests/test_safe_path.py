import pytest

from safe_path import safe_join


@pytest.mark.parametrize(
    "base,user_path,expected",
    [
        ("/srv/data", "reports/q1.txt", "/srv/data/reports/q1.txt"),
        ("/srv/data/", "a/./b/../c", "/srv/data/a/c"),
        ("/srv/data", "", "/srv/data"),
        ("/srv/data", ".", "/srv/data"),
        ("/srv/data", "a//b/", "/srv/data/a/b"),
        ("/srv/data", "a/..", "/srv/data"),
        ("/srv/data", "../data/x", "/srv/data/x"),
        ("/srv/./data", "x", "/srv/data/x"),
        ("/", "etc/passwd", "/etc/passwd"),
        ("/", "..", "/"),
        ("/srv/data", "a\\..\\b", "/srv/data/a\\..\\b"),
    ],
)
def test_safe_join_inside(base, user_path, expected):
    assert safe_join(base, user_path) == expected


@pytest.mark.parametrize(
    "base,user_path",
    [
        ("/srv/data", "../etc/passwd"),
        ("/srv/data", "/etc/passwd"),
        ("/srv/data", "/srv/data/x"),
        ("/srv/data", ".."),
        ("/srv/data", "a/../../x"),
        ("/srv/data", "../data2/x"),
        ("/srv/data", "x\x00y"),
        ("srv/data", "x"),
        ("", "x"),
    ],
)
def test_safe_join_rejects(base, user_path):
    with pytest.raises(ValueError):
        safe_join(base, user_path)


def test_type_errors():
    with pytest.raises(TypeError):
        safe_join(b"/srv", "x")
    with pytest.raises(TypeError):
        safe_join("/srv", None)
