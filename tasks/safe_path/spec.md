# Safe path join

Implement in `safe_path.py`:

```python
def safe_join(base: str, user_path: str) -> str: ...
```

Join an untrusted relative `user_path` onto a trusted directory `base`, refusing anything
that would land outside `base`. POSIX semantics (`/` is the only separator; backslash is an
ordinary character). Purely lexical: never touches the filesystem, does not resolve symlinks,
does not check existence, and must not depend on the environment or current directory.

## Behavior (checked in this order)
1. Both arguments must be `str`, else raise `TypeError`.
2. Raise `ValueError` if either argument contains a NUL character (`"\x00"`).
3. Raise `ValueError` if `base` is not absolute (does not start with `/`).
4. Raise `ValueError` if `user_path` is absolute (starts with `/`), even if it points inside `base`.
5. Let `root = posixpath.normpath(base)` and
   `result = posixpath.normpath(posixpath.join(root, user_path))`.
6. `result` is **inside** base iff `result == root` or `result` starts with `root + "/"`
   (when `root` already ends in `/`, e.g. `root == "/"`, it must start with `root`).
   A sibling sharing a name prefix is OUTSIDE: for base `/srv/data`, `/srv/data2/x` is outside.
7. Return `result` if it is inside, otherwise raise `ValueError`. Only the final normalized
   result is checked: `..` segments are fine as long as the result stays inside.
- An empty `user_path` or `"."` returns `root`.

## Examples
- `safe_join("/srv/data", "reports/q1.txt") == "/srv/data/reports/q1.txt"`
- `safe_join("/srv/data/", "a/./b/../c") == "/srv/data/a/c"`
- `safe_join("/srv/data", "") == "/srv/data"`
- `safe_join("/srv/data", "../etc/passwd")` raises `ValueError`
- `safe_join("/srv/data", "/etc/passwd")` raises `ValueError`
