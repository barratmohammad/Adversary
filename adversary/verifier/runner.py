"""Run a pytest suite inside the sandbox and parse per-test outcomes from JUnit XML.

The verifier's suite runs hardened against tampering by the change under test:
  * `python -I`        - isolated mode: no PYTHONPATH, no user site, cwd not on sys.path at
                         startup, so a planted sitecustomize.py / usercustomize.py never loads
  * `-c <our ini>`     - the implementer's pytest.ini / pyproject / setup.cfg addopts are ignored
  * `--noconftest`     - the implementer's conftest.py hooks cannot rewrite our test reports
  * seeded Hypothesis  - `--hypothesis-seed`, example database disabled
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from ..sandbox import Sandbox

VERIFIER_DIR = "adversary_tests"

VERIFIER_INI = """[pytest]
pythonpath = ..
addopts =
python_files = test_*.py
"""

HYPOTHESIS_HEADER = '''# --- adversary: pinned hypothesis profile (prepended by the verifier) ---
import os as _adv_os
from hypothesis import settings as _adv_settings, HealthCheck as _adv_HC, Phase as _adv_Phase
_adv_settings.register_profile(
    "adversary",
    max_examples=int(_adv_os.environ.get("ADVERSARY_MAX_EXAMPLES", "200")),
    deadline=None,
    database=None,
    print_blob=False,
    suppress_health_check=list(_adv_HC),
    phases=[_adv_Phase.explicit, _adv_Phase.reuse, _adv_Phase.generate, _adv_Phase.shrink],
)
_adv_settings.load_profile("adversary")
# --- end adversary header ---
'''


@dataclass
class TestOutcome:
    nodeid: str
    name: str
    status: str  # passed | failed | error | skipped
    message: str = ""
    detail: str = ""
    falsifying: str = ""
    duration: float = 0.0


@dataclass
class SuiteResult:
    outcomes: list[TestOutcome] = field(default_factory=list)
    returncode: int = 0
    timed_out: bool = False
    collection_error: str = ""
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0

    @property
    def passed(self) -> list[TestOutcome]:
        return [o for o in self.outcomes if o.status == "passed"]

    @property
    def failed(self) -> list[TestOutcome]:
        return [o for o in self.outcomes if o.status in ("failed", "error")]

    @property
    def ok(self) -> bool:
        return not self.timed_out and not self.collection_error and not self.failed and bool(self.outcomes)

    def summary(self) -> dict:
        return {
            "total": len(self.outcomes),
            "passed": len(self.passed),
            "failed": len(self.failed),
            "timed_out": self.timed_out,
            "collection_error": self.collection_error[:500],
        }


FALSIFY_RE = re.compile(r"(?:Falsifying (?:explicit )?example|Failing test case):\s*(\w+\((?:.|\n)*?\n?\s*\))", re.S)


def _falsifying(*texts: str) -> str:
    for t in texts:
        if not t:
            continue
        clean = re.sub(r"(?m)^E\s{0,3}", "", t)
        m = FALSIFY_RE.search(clean)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).replace("( ", "(").replace(", )", ")")[:800]
    return ""


def _parse_junit(path: Path) -> list[TestOutcome]:
    if not path.exists():
        return []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return []
    outs = []
    for tc in root.iter("testcase"):
        cls, name = tc.get("classname", ""), tc.get("name", "")
        nodeid = f"{cls}::{name}" if cls else name
        status, message, detail = "passed", "", ""
        for tag in ("failure", "error", "skipped"):
            el = tc.find(tag)
            if el is not None:
                status = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
                message = el.get("message", "") or ""
                detail = el.text or ""
                break
        outs.append(TestOutcome(
            nodeid=nodeid, name=name, status=status,
            message=message[:2000], detail=detail[-4000:],
            falsifying=_falsifying(message, detail),
            duration=float(tc.get("time", 0) or 0),
        ))
    return outs


def run_suite(
    sandbox: Sandbox,
    workdir: Path,
    target: str,
    seed: int,
    timeout: float = 180.0,
    hardened: bool = True,
    max_examples: int = 200,
    junit_name: str = "junit.xml",
) -> SuiteResult:
    """Run pytest on `target` (path relative to workdir)."""
    junit = Path(".tmp") / junit_name
    (workdir / ".tmp").mkdir(exist_ok=True)
    (workdir / junit).unlink(missing_ok=True)
    args = []
    if hardened:
        args += ["-I", "-m", "pytest", "-c", f"{VERIFIER_DIR}/pytest.ini", "--rootdir", VERIFIER_DIR, "--noconftest"]
    else:
        # The implementer's suite runs "as submitted" (its own ini/conftest), but pytest must never walk
        # up out of the workspace and pick up a config from wherever the workspace happens to live.
        ini = next((n for n in ("pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg") if (workdir / n).exists()), None)
        if ini is None and (workdir / "pyproject.toml").exists() and "[tool.pytest" in (workdir / "pyproject.toml").read_text():
            ini = "pyproject.toml"
        if ini is None:
            (workdir / ".tmp" / "pytest.ini").write_text("[pytest]\n")
            ini = ".tmp/pytest.ini"
        args += ["-m", "pytest", "-c", ini, "--rootdir", "."]
    args += [
        "-q", "-p", "no:cacheprovider", "-p", "no:randomly",
        f"--hypothesis-seed={seed}", f"--junitxml={junit}",
        "-o", "junit_family=xunit1", "--tb=short", target,
    ]
    rr = sandbox.run(args, cwd=workdir, timeout=timeout, env={"ADVERSARY_MAX_EXAMPLES": str(max_examples)})
    res = SuiteResult(returncode=rr.returncode, timed_out=rr.timed_out, stdout=rr.stdout[-6000:], stderr=rr.stderr[-3000:], duration=rr.duration)
    res.outcomes = _parse_junit(workdir / junit)
    if not rr.timed_out and rr.returncode in (2, 3, 4) or (not res.outcomes and not rr.timed_out and rr.returncode != 5):
        res.collection_error = (rr.stdout + "\n" + rr.stderr).strip()[-3000:] or f"pytest exited {rr.returncode}"
    if rr.returncode == 5:
        res.collection_error = "no tests collected"
    return res


def install_verifier_suite(workdir: Path, test_files: dict[str, str]) -> None:
    d = workdir / VERIFIER_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / "pytest.ini").write_text(VERIFIER_INI)
    (d / "__init__.py").write_text("")
    for name, src in test_files.items():
        (d / name).write_text(src)
