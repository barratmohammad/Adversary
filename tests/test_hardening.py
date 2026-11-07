"""Fail-open paths found by the red-team pass must stay closed (no model calls)."""
from pathlib import Path

import pytest

from adversary.verifier import pipeline, runner
from adversary.verifier.runner import SuiteResult, TestOutcome
from adversary.workspace import Change, write_tree

ROMAN = {"roman.py": "def to_roman(n):\n    return 'I' * n\n"}


def _res(**kw) -> SuiteResult:
    r = SuiteResult()
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _out(name, status="passed"):
    return TestOutcome(nodeid=name, name=name, status=status, message="", detail="", falsifying="", duration=0.0)


def test_timeout_is_no_evidence_not_a_pass(tmp_path):
    ch = Change(base=ROMAN, after=ROMAN)
    write_tree(tmp_path, ROMAN)
    r = _res(timed_out=True, outcomes=[])
    pipeline._harden_result(r, tmp_path, ch)
    assert r.collection_error and not r.outcomes


def test_interrupted_session_with_partial_passes_is_discarded(tmp_path):
    ch = Change(base=ROMAN, after=ROMAN)
    write_tree(tmp_path, ROMAN)
    r = _res(collection_error="!!! KeyboardInterrupt !!!", outcomes=[_out("t1"), _out("t2")])
    pipeline._harden_result(r, tmp_path, ch)
    assert not r.outcomes and "did not complete" in r.collection_error


def test_skipped_blind_tests_block(tmp_path):
    ch = Change(base=ROMAN, after=ROMAN)
    write_tree(tmp_path, ROMAN)
    r = _res(outcomes=[_out("t1"), _out("t2", "skipped")])
    pipeline._harden_result(r, tmp_path, ch)
    assert not r.outcomes and "skipped" in r.collection_error


def test_tree_modified_during_blind_suite_blocks(tmp_path):
    ch = Change(base=ROMAN, after=ROMAN)
    write_tree(tmp_path, ROMAN)
    (tmp_path / "roman.py").write_text("def to_roman(n):\n    return 'correct now'\n")   # rewritten by a test
    r = _res(outcomes=[_out("t1")])
    pipeline._harden_result(r, tmp_path, ch)
    assert not r.outcomes and "modified" in r.collection_error


def test_clean_result_is_left_alone(tmp_path):
    ch = Change(base=ROMAN, after=ROMAN)
    write_tree(tmp_path, ROMAN)
    r = _res(outcomes=[_out("t1"), _out("t2")])
    pipeline._harden_result(r, tmp_path, ch)
    assert len(r.outcomes) == 2 and not r.collection_error


def test_structural_findings_catch_verifier_dir_shadowing_and_tests_import():
    after = dict(ROMAN)
    after["adversary_tests/test_aaa.py"] = "import sys\n"
    after["hypothesis/__init__.py"] = "given = lambda *a, **k: (lambda f: f)\n"
    after["roman.py"] = "from tests._impl import to_roman\n"
    ch = Change(base=ROMAN, after=after)
    rules = {f["rule"] for f in pipeline._structural_findings(ch)}
    assert {"verifier-dir", "shadows-module", "impl-imports-tests"} <= rules
    assert pipeline._structural_findings(Change(base=ROMAN, after=ROMAN)) == []


def test_junit_without_pytest_summary_is_discarded():
    assert runner._PYTEST_SUMMARY.search("108 passed in 1.8s")
    assert runner._PYTEST_SUMMARY.search("3 failed, 105 passed in 2.0s")
    assert not runner._PYTEST_SUMMARY.search("")             # os._exit(0) before the summary
    assert runner._safe_float("abc") == 0.0 and runner._safe_float("1.5") == 1.5


def test_write_tree_refuses_path_escape(tmp_path):
    with pytest.raises(ValueError):
        write_tree(tmp_path, {"../escape.py": "x = 1\n"})
    with pytest.raises(ValueError):
        write_tree(tmp_path, {"/abs.py": "x = 1\n"})
    assert not (tmp_path.parent / "escape.py").exists()
