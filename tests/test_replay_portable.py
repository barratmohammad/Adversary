"""Replay must work on a machine that lacks the recording machine's .env.

The cassette key includes provider/model, which a clean clone resolves differently. In replay mode a miss
falls back to a content match (messages + parameters), and the Completion reports the recorded model.
"""
import json

import pytest

from adversary import llm
from adversary.hashing import sha256_json


@pytest.fixture
def cassettes(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "CASSETTE_DIR", tmp_path)
    monkeypatch.setattr(llm, "_CONTENT_INDEX", None)
    monkeypatch.setenv("ADVERSARY_LLM_MODE", "replay")
    return tmp_path


def _record(d, provider, model, messages, text, temperature=0.0, max_tokens=24000):
    req = {"provider": provider, "model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    h = sha256_json(req)
    (d / f"{h}.json").write_text(json.dumps({"request": req, "text": text, "tag": "t"}))
    return h


def test_replay_hits_recording_made_under_another_provider_name(cassettes, monkeypatch):
    msgs = [{"role": "user", "content": "write tests for roman"}]
    h = _record(cassettes, "meta", "muse-spark-1.3", msgs, "RECORDED TESTS")
    monkeypatch.setenv("ADVERSARY_VERIFIER_PROVIDER", "gemini")      # what a keyless clone would resolve to
    monkeypatch.setenv("ADVERSARY_VERIFIER_MODEL", "gemini-2.5-flash")
    c = llm.chat("verifier", msgs, temperature=0.0, max_tokens=24000)
    assert c.text == "RECORDED TESTS" and c.cached
    assert c.model == "muse-spark-1.3" and c.request_hash == h  # reports what actually answered


def test_replay_does_not_match_a_different_prompt_or_parameters(cassettes, monkeypatch):
    msgs = [{"role": "user", "content": "write tests for roman"}]
    _record(cassettes, "meta", "muse-spark-1.3", msgs, "RECORDED TESTS")
    monkeypatch.setenv("ADVERSARY_VERIFIER_PROVIDER", "gemini")
    with pytest.raises(llm.LLMError):
        llm.chat("verifier", [{"role": "user", "content": "something else"}], temperature=0.0, max_tokens=24000)
    with pytest.raises(llm.LLMError):
        llm.chat("verifier", msgs, temperature=0.5, max_tokens=24000)


def test_exact_hash_still_wins_over_content_match(cassettes, monkeypatch):
    msgs = [{"role": "user", "content": "same prompt"}]
    _record(cassettes, "meta", "muse-spark-1.3", msgs, "FROM META")
    _record(cassettes, "gemini", "gemini-2.5-flash", msgs, "FROM GEMINI")
    monkeypatch.setenv("ADVERSARY_VERIFIER_PROVIDER", "gemini")
    monkeypatch.setenv("ADVERSARY_VERIFIER_MODEL", "gemini-2.5-flash")
    assert llm.chat("verifier", msgs, temperature=0.0, max_tokens=24000).text == "FROM GEMINI"
