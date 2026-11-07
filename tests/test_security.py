"""Tests for adversary.verifier.security (true positives + false positives)."""

from __future__ import annotations

import textwrap

import pytest

from adversary.verifier.security import SecurityFinding, scan


def run(src: str, path: str = "mod.py", **kw) -> list[SecurityFinding]:
    return scan({path: textwrap.dedent(src)}, **kw)


def rules(src: str, **kw) -> set[str]:
    return {f.rule for f in run(src, **kw)}


def find(src: str, rule: str, **kw) -> list[SecurityFinding]:
    return [f for f in run(src, **kw) if f.rule == rule]


# --------------------------------------------------------------------------- #
# Clean code -> zero findings
# --------------------------------------------------------------------------- #

CLEAN_SOURCES = [
    # roman-style pure function
    '''
    import re

    _NUMERALS = [(1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"),
                 (90, "XC"), (50, "L"), (40, "XL"), (10, "X"), (9, "IX"),
                 (5, "V"), (4, "IV"), (1, "I")]
    _CANONICAL = re.compile(r"M{0,3}(CM|CD|D?C{0,3})(XC|XL|L?X{0,3})(IX|IV|V?I{0,3})")

    def to_roman(n: int) -> str:
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError("n must be an int")
        if not 1 <= n <= 3999:
            raise ValueError("out of range")
        out = []
        for value, numeral in _NUMERALS:
            while n >= value:
                out.append(numeral)
                n -= value
        return "".join(out)
    ''',
    # interval merge with sorting / max
    '''
    def merge_intervals(intervals):
        for start, end in intervals:
            if start > end:
                raise ValueError("bad interval")
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged
    ''',
    # correctly sanitized path join
    '''
    import posixpath

    def safe_join(base: str, user_path: str) -> str:
        root = posixpath.normpath(base)
        candidate = posixpath.normpath(posixpath.join(root, user_path))
        prefix = root if root.endswith("/") else root + "/"
        if candidate != root and not candidate.startswith(prefix):
            raise ValueError("escapes base")
        return candidate
    ''',
    # pathlib sanitized
    '''
    from pathlib import Path

    def resolve_inside(base: Path, name: str) -> Path:
        target = (Path(base) / name).resolve()
        if not target.is_relative_to(Path(base).resolve()):
            raise ValueError("escape")
        return target
    ''',
    # benign stuff that superficially resembles rules
    '''
    import re
    import hashlib
    import secrets
    import json

    PATTERN = re.compile(r"[a-z]+")
    TOKEN_TYPE = "bearer"
    password_field = "password"
    API_KEY_ENV = "OPENAI_API_KEY"

    def tokenize(text):
        token = "("
        tokens = [t for t in PATTERN.findall(text)]
        return [token] + tokens

    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def checksum(data: bytes) -> str:
        return hashlib.md5(data, usedforsecurity=False).hexdigest()

    def make_token() -> str:
        return secrets.token_hex(16)

    def parse(s: str):
        requests = []
        requests.append(json.loads(s))
        return requests

    def average(total, n):
        return total / n

    def read_config(path):
        with open(path) as fh:
            return fh.read()

    def read_bytes(path):
        with open(path, "rb") as fh:
            return fh.read()
    ''',
    # long prose docstring must not look like base64
    '"""' + ("This is a long human readable docstring. " * 10) + '"""\n',
]


@pytest.mark.parametrize("src", CLEAN_SOURCES)
def test_clean_code_has_no_findings(src):
    assert run(src) == []


def test_empty_and_no_files():
    assert scan({}) == []
    assert scan({"empty.py": ""}) == []


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


def test_syntax_error_is_single_low_finding():
    out = scan({"broken.py": "def f(:\n    pass\n"})
    assert len(out) == 1
    assert out[0].rule == "syntax-error" and out[0].severity == "low"
    assert out[0].path == "broken.py"


def test_never_raises_on_weird_input():
    out = scan({"a.py": "x = 1\x00\n", "b.py": None, "c.py": b"import os\nos.system(cmd)\n"})  # type: ignore[dict-item]
    assert all(isinstance(f, SecurityFinding) for f in out)
    assert any(f.rule == "shell-injection" for f in out)


def test_sorted_by_severity_path_lineno():
    out = scan({
        "b.py": "import hashlib\nhashlib.md5(b'x')\neval(x)\n",
        "a.py": "import subprocess\nsubprocess.run(['ls'])\nexec(code)\n",
    })
    keys = [({"high": 0, "medium": 1, "low": 2}[f.severity], f.path, f.lineno) for f in out]
    assert keys == sorted(keys)
    assert out[0].severity == "high"


def test_snippet_is_stripped_and_truncated():
    src = "    eval(" + "x" * 300 + ")\n"
    out = scan({"m.py": "def f(x):\n" + src})
    f = next(f for f in out if f.rule == "dynamic-exec")
    assert f.snippet.startswith("eval(") and len(f.snippet) <= 160
    assert f.lineno == 2


# --------------------------------------------------------------------------- #
# High-severity rules
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("src", [
    "eval(user_input)\n",
    "exec(code)\n",
    "compile(src, '<x>', 'exec')\n",
    "import builtins\nbuiltins.eval(x)\n",
    "__import__(name)\n",
    "import importlib\nimportlib.import_module(name)\n",
])
def test_dynamic_exec(src):
    f = find(src, "dynamic-exec")
    assert f and f[0].severity == "high"


@pytest.mark.parametrize("src", [
    "eval('1 + 1')\n",
    "import re\nre.compile(pattern)\n",
    "from re import compile\ncompile(pattern)\n",
    "import importlib\nimportlib.import_module('json')\n",
])
def test_dynamic_exec_false_positives(src):
    assert "dynamic-exec" not in rules(src)


@pytest.mark.parametrize("src", [
    "import pickle\npickle.loads(blob)\n",
    "import pickle\npickle.load(fh)\n",
    "from pickle import loads\nloads(blob)\n",
    "import marshal\nmarshal.loads(blob)\n",
    "import yaml\nyaml.load(text)\n",
    "import yaml\nyaml.load(text, Loader=yaml.Loader)\n",
    "import shelve\nshelve.open('db')\n",
])
def test_unsafe_deserialization(src):
    f = find(src, "unsafe-deserialization")
    assert f and f[0].severity == "high"


@pytest.mark.parametrize("src", [
    "import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n",
    "import yaml\nyaml.safe_load(text)\n",
    "import json\njson.loads(text)\n",
])
def test_safe_deserialization(src):
    assert "unsafe-deserialization" not in rules(src)


@pytest.mark.parametrize("src,severity", [
    ("import os\nos.system('rm -rf ' + p)\n", "high"),
    ("import os\nos.popen(cmd)\n", "high"),
    ("import subprocess\nsubprocess.run(cmd, shell=True)\n", "high"),
    ("import subprocess as sp\nsp.Popen(cmd, shell=True)\n", "high"),
    ("from subprocess import check_output\ncheck_output(cmd, shell=True)\n", "high"),
    ("import subprocess\nsubprocess.run(['ls', '-l'])\n", "medium"),
    ("import subprocess\nsubprocess.run(['ls'], shell=False)\n", "medium"),
])
def test_shell_injection(src, severity):
    f = find(src, "shell-injection")
    assert f and f[0].severity == severity


@pytest.mark.parametrize("src", [
    "import socket\n",
    "import requests\nrequests.get(url)\n",
    "import httpx\n",
    "import urllib.request\n",
    "from urllib.request import urlopen\n",
    "from urllib import request\n",
    "import urllib\nurllib.request.urlopen(url)\n",
    "import http.client\n",
    "import smtplib\n",
    "import aiohttp\n",
    "__import__('socket').socket()\n",
])
def test_network_access(src):
    f = find(src, "network-access")
    assert f and all(x.severity == "high" for x in f)


def test_network_allowed_and_non_network_imports():
    assert "network-access" not in rules("import requests\nrequests.get(u)\n", allow_network=True)
    assert "network-access" not in rules("import urllib.parse\nurllib.parse.quote(s)\n")
    assert "network-access" not in rules("from urllib.parse import urljoin\n")
    # import reported once, not again at every call site
    assert len(find("import requests\nrequests.get(u)\nrequests.post(u)\n", "network-access")) == 1


@pytest.mark.parametrize("src", [
    "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
    "import base64\npayload = base64.b64decode(blob)\ncode = payload.decode()\nexec(code)\n",
    "import zlib\neval(zlib.decompress(data))\n",
    "exec(bytes.fromhex('7072696e74283129'))\n",
    "import codecs\nexec(codecs.decode(s, 'rot13'))\n",
    "exec(s.decode('rot13'))\n",
])
def test_obfuscated_exec(src):
    f = find(src, "obfuscated-code")
    assert f and f[0].severity == "high"
    assert "dynamic-exec" in rules(src)


def test_long_base64_literal():
    import base64

    blob = base64.b64encode(bytes(range(256)) * 2).decode()
    f = find(f"BLOB = {blob!r}\n", "obfuscated-code")
    assert f and f[0].severity == "high"
    hexblob = bytes(range(200)).hex()
    assert find(f"H = {hexblob!r}\n", "obfuscated-code")
    # short base64 / decoding without exec is fine
    assert "obfuscated-code" not in rules("import base64\nx = base64.b64decode('aGk=')\n")


@pytest.mark.parametrize("src,severity", [
    # hidden admin mode returning a different result -> high
    ('''
    import os
    def check(user):
        if os.environ.get("ADV_DEBUG_ROOT"):
            return True
        return user == "admin"
    ''', "high"),
    # module-level flag, used later
    ('''
    import os
    _DEBUG = os.getenv("DEBUG_MODE") == "1"
    def safe_join(base, p):
        if _DEBUG:
            return base + "/" + p
        return base
    ''', "high"),
    # aliased import
    ('''
    from os import environ
    def f(x):
        if "BACKDOOR" in environ:
            exec(x)
        return x
    ''', "high"),
    # helper function that reads the env
    ('''
    import os
    def _legacy():
        return os.environ.get("LEGACY") == "1"
    def f(x):
        if _legacy():
            return -x
        return x
    ''', "high"),
    # env value returned directly from a function with inputs
    ('''
    import os
    def root(base):
        return os.environ.get("ROOT_OVERRIDE") or base
    ''', "high"),
    # conditional expression in a return
    ('''
    import os
    def f(x):
        return x if not os.getenv("FLIP") else -x
    ''', "high"),
    # benign branch -> medium
    ('''
    import os
    def f(x):
        if os.getenv("VERBOSE"):
            print("computing", x)
        y = x * 2
        return y
    ''', "medium"),
])
def test_env_triggered_behavior(src, severity):
    f = find(src, "env-triggered-behavior")
    assert f, run(src)
    assert max(f, key=lambda x: x.severity == "high").severity == severity


@pytest.mark.parametrize("src", [
    'AWS = "AKIAIOSFODNN7EXAMPLE"\n',
    'key = "sk-abcdefghijklmnopqrstuvwxyz123456"\n',
    'gh = "ghp_' + "a" * 36 + '"\n',
    '"""-----BEGIN RSA PRIVATE KEY-----"""\n',
    'password = "hunter22"\n',
    'DB_PASSWORD = "s3cr3t!"\n',
    'api_key = "abcd1234efgh"\n',
    'self_secret = "topsecret"\n',
    'class C:\n    apiKey = "abcd1234"\n',
    'cfg = {"password": "hunter22"}\n',
    'auth_token = "abc123def456"\n',
])
def test_hardcoded_secret(src):
    f = find(src, "hardcoded-secret")
    assert f and f[0].severity == "high"


@pytest.mark.parametrize("src", [
    'password = ""\n',
    'password = os.environ["PASSWORD"]\n',
    'password_field = "password"\n',
    'SECRET_ENV = "MY_SECRET"\n',
    'token = "NUMBER"\n',
    'msg = "enter your password please"\n',
])
def test_hardcoded_secret_false_positives(src):
    assert "hardcoded-secret" not in rules(src)


# --------------------------------------------------------------------------- #
# Medium-severity rules
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("src", [
    "open(p, 'w')\n",
    "open(p, mode='a')\n",
    "open(p, 'xb')\n",
    "open(p, 'r+')\n",
    "from pathlib import Path\nPath(p).write_text('x')\n",
    "from pathlib import Path\nPath(p).write_bytes(b'x')\n",
    "p.unlink()\n",
    "import os\nos.remove(p)\n",
    "import shutil\nshutil.rmtree(d)\n",
    "from pathlib import Path\nPath(p).open('w')\n",
])
def test_fs_write(src):
    f = find(src, "file-system-write")
    assert f and f[0].severity == "medium"


@pytest.mark.parametrize("src", [
    "open(p)\n",
    "open(p, 'rb')\n",
    "import webbrowser\nwebbrowser.open('http://x')\n",
    "z.open('file.txt')\n",
])
def test_fs_read_is_not_write(src):
    assert "file-system-write" not in rules(src)


def test_fs_write_allowed():
    assert "file-system-write" not in rules("open(p, 'w')\n", allow_fs_write=True)


@pytest.mark.parametrize("src", [
    '''
    import os
    def load(base, name):
        return open(os.path.join(base, name)).read()
    ''',
    '''
    from pathlib import Path
    def load(base, name):
        return (Path(base) / name).read_text()
    ''',
    '''
    import os
    def load(base, name):
        full = os.path.abspath(os.path.join(base, name))
        return full
    ''',
])
def test_path_traversal(src):
    f = find(src, "path-traversal")
    assert f and f[0].severity == "medium"


@pytest.mark.parametrize("src", [
    '''
    import os
    def load(base, name):
        full = os.path.realpath(os.path.join(base, name))
        if not full.startswith(os.path.realpath(base) + os.sep):
            raise ValueError
        return full
    ''',
    '''
    import os
    def config_path(base_dir):
        return os.path.join(base_dir, "config.json")
    ''',
    # containment check delegated to a helper
    '''
    import posixpath
    def _inside(root, cand):
        return cand == root or cand.startswith(root + "/")
    def safe_join(base, user_path):
        root = posixpath.normpath(base)
        cand = posixpath.normpath(posixpath.join(root, user_path))
        if not _inside(root, cand):
            raise ValueError(user_path)
        return cand
    ''',
])
def test_path_traversal_false_positives(src):
    assert "path-traversal" not in rules(src)


def test_insecure_tempfile():
    f = find("import tempfile\nname = tempfile.mktemp()\n", "insecure-tempfile")
    assert f and f[0].severity == "medium"


# --------------------------------------------------------------------------- #
# Low-severity rules
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("src", [
    "import hashlib\nhashlib.md5(data)\n",
    "import hashlib\nhashlib.sha1(data).hexdigest()\n",
    "from hashlib import md5\nmd5(data)\n",
    "import hashlib\nhashlib.new('md5')\n",
])
def test_weak_crypto(src):
    f = find(src, "weak-crypto")
    assert f and f[0].severity == "low"


@pytest.mark.parametrize("src", [
    "import random\ndef make_token():\n    return random.getrandbits(64)\n",
    "import random\nsession_id = random.randint(0, 10**9)\n",
    "import random, string\npassword = ''.join(random.choices(string.ascii_letters, k=12))\n",
    "import random\ndef f():\n    salt = random.random()\n    return salt\n",
])
def test_insecure_random(src):
    f = find(src, "insecure-random")
    assert f and f[0].severity == "low"


@pytest.mark.parametrize("src", [
    "import random\ndef shuffle_deck(cards):\n    random.shuffle(cards)\n    return cards\n",
    "import random\nx = random.randint(1, 6)\n",
    "import random\nrng = random.Random(0)\n",
])
def test_random_false_positives(src):
    assert "insecure-random" not in rules(src)


def test_assert_validation():
    src = '''
    def delete(user, item):
        assert user.is_admin
        assert item is not None
        return item
    '''
    f = find(src, "assert-validation")
    assert f and all(x.severity == "low" for x in f)
    assert not find("def f():\n    x = compute()\n    assert x\n    return x\n", "assert-validation")


def test_finding_fields():
    out = scan({"pkg/mod.py": "import os\n\ndef f(cmd):\n    os.system(cmd)\n"})
    assert len(out) == 1
    f = out[0]
    assert (f.rule, f.path, f.lineno, f.severity) == ("shell-injection", "pkg/mod.py", 4, "high")
    assert f.snippet == "os.system(cmd)"
    assert f.message
