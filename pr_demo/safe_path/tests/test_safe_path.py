import pytest

from safe_path import safe_join


def test_basic_join():
    assert safe_join("/srv/data", "reports/q1.txt") == "/srv/data/reports/q1.txt"


def test_normalization():
    assert safe_join("/srv/data/", "a/./b/../c") == "/srv/data/a/c"


def test_empty_and_dot_return_root():
    assert safe_join("/srv/data", "") == "/srv/data"
    assert safe_join("/srv/data", ".") == "/srv/data"
    assert safe_join("/srv/data/", "") == "/srv/data"
    assert safe_join("/srv/data//", "./") == "/srv/data"


def test_escape_raises():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "../etc/passwd")


def test_absolute_user_path_raises_even_inside():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "/etc/passwd")
    with pytest.raises(ValueError):
        safe_join("/srv/data", "/srv/data/file.txt")


def test_relative_base_raises():
    with pytest.raises(ValueError):
        safe_join("srv/data", "file.txt")
    with pytest.raises(ValueError):
        safe_join("", "file.txt")
    with pytest.raises(ValueError):
        safe_join("./srv", "file.txt")


def test_type_errors():
    with pytest.raises(TypeError):
        safe_join(None, "a")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join("/srv/data", None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join(b"/srv/data", "a")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join("/srv/data", 123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        safe_join(123, "a")  # type: ignore[arg-type]


def test_nul_raises():
    with pytest.raises(ValueError):
        safe_join("/srv/data\x00", "a")
    with pytest.raises(ValueError):
        safe_join("/srv/data", "a\x00b")


def test_check_order_type_before_value():
    # Non-str containing check would fail differently; TypeError takes precedence
    with pytest.raises(TypeError):
        safe_join(None, "\x00")  # type: ignore[arg-type]


def test_sibling_prefix_is_outside():
    with pytest.raises(ValueError):
        safe_join("/srv/data", "../data2/x")
    with pytest.raises(ValueError):
        safe_join("/srv/data", "../data2")


def test_dotdot_staying_inside_is_allowed():
    assert safe_join("/srv/data", "a/../b") == "/srv/data/b"
    assert safe_join("/srv/data", "a/b/../../c") == "/srv/data/c"
    assert safe_join("/srv/data", "a/..") == "/srv/data"


def test_dotdot_escaping_variants():
    for p in ["..", "../", "a/../../b", "../../etc/passwd", "a/b/../../../c"]:
        with pytest.raises(ValueError):
            safe_join("/srv/data", p)


def test_root_base():
    assert safe_join("/", "etc/passwd") == "/etc/passwd"
    assert safe_join("/", "") == "/"
    assert safe_join("/", ".") == "/"
    assert safe_join("/", "a/../b") == "/b"
    with pytest.raises(ValueError):
        safe_join("/", "../etc")
    with pytest.raises(ValueError):
        safe_join("/", "/etc/passwd")


def test_backslash_is_ordinary_character():
    # Backslash is not a separator under POSIX semantics
    assert safe_join("/srv/data", "a\\..\\b") == "/srv/data/a\\..\\b"
    assert safe_join("/srv/data", "..\\etc") == "/srv/data/..\\etc"


def test_base_normalization():
    assert safe_join("/srv//data/./x/..", "file") == "/srv/data/file"
    assert safe_join("/srv/data/../data", "file") == "/srv/data/file"


def test_nested_and_trailing():
    assert safe_join("/srv/data", "a/b/") == "/srv/data/a/b"
    assert safe_join("/srv/data", "a//b") == "/srv/data/a/b"
