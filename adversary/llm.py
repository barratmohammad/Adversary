"""Minimal OpenAI-compatible chat client with role-separated config and a record/replay cassette.

Roles are configured independently so the implementer and the verifier can (and by default
should) run on *different model families* - the verifier must not share the implementer's
blind spots.

  verifier (writes the blind tests)   -> Meta Model API, muse-spark      (ADVERSARY_VERIFIER_PROVIDER)
  implementer                        -> gemini/anthropic/openai if keyed, else meta (ADVERSARY_IMPLEMENTER_PROVIDER)
  adjudicator                        -> Subquadratic SubQ Snap decisions API (adversary/decisions.py)

Per-role overrides: ADVERSARY_<ROLE>_BASE_URL / _API_KEY / _MODEL.

Cassette: every completion is stored under .adversary/cassettes/<sha256(request)>.json.
ADVERSARY_LLM_MODE=auto (default: replay if recorded, else call+record) | replay | live.
Replay makes runs reproducible and the demo independent of venue Wi-Fi.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .hashing import sha256_json

ROOT = Path(__file__).resolve().parent.parent
CASSETTE_DIR = Path(os.environ.get("ADVERSARY_CASSETTES", ROOT / ".adversary" / "cassettes"))

PROVIDERS: dict[str, dict] = {
    "meta": {"base_url": "https://api.meta.ai/v1", "key_env": ["MODEL_API_KEY", "META_API_KEY"], "model": "muse-spark-1.3"},
    "gemini": {"base_url": "https://generativelanguage.googleapis.com/v1beta/openai", "key_env": ["GEMINI_API_KEY", "GOOGLE_API_KEY"], "model": "gemini-2.5-flash"},
    "subq": {"base_url": "https://api.subq.ai/v1", "key_env": ["SUBQ_API_KEY", "SUBQUADRATIC_API_KEY"], "model": "subq-snap-1.1"},
    "fireworks": {"base_url": "https://api.fireworks.ai/inference/v1", "key_env": ["FIREWORKS_API_KEY"], "model": "accounts/fireworks/models/qwen3-coder-480b-a35b-instruct"},
    "openai": {"base_url": "https://api.openai.com/v1", "key_env": ["OPENAI_API_KEY"], "model": "gpt-4.1"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "key_env": ["ANTHROPIC_API_KEY"], "model": "claude-sonnet-5-5"},
}


class LLMError(RuntimeError):
    pass


def _read_env_file(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        m = re.match(r"\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$", line)
        if m and m.group(1) not in os.environ:
            os.environ[m.group(1)] = m.group(2).strip().strip('"').strip("'")


def _load_dotenv() -> None:
    _read_env_file(ROOT / ".env")
    # .env.replay pins the roles to the providers/models the committed cassettes were recorded with.
    # It applies in replay mode, and on a machine with no API key at all (which can only replay anyway),
    # so a clean clone shows the same models and hits the same recordings as the machine that made them.
    any_key = any(os.environ.get(k) for p in PROVIDERS.values() for k in p["key_env"])
    if os.environ.get("ADVERSARY_LLM_MODE") == "replay" or not any_key:
        _read_env_file(ROOT / ".env.replay")


_load_dotenv()


def _key_for(provider: str) -> str | None:
    for k in PROVIDERS.get(provider, {}).get("key_env", []):
        if os.environ.get(k):
            return os.environ[k]
    return None


@dataclass
class ModelConfig:
    role: str
    provider: str
    base_url: str
    model: str
    api_key: str | None

    def describe(self) -> dict:
        return {"role": self.role, "provider": self.provider, "model": self.model, "base_url": self.base_url}


def config_for(role: str) -> ModelConfig:
    R = role.upper()
    provider = os.environ.get(f"ADVERSARY_{R}_PROVIDER")
    if not provider:
        if role == "implementer":
            # implementer: a different family from the verifier's test author (Meta) when possible
            provider = next((p for p in ("gemini", "anthropic", "openai", "fireworks") if _key_for(p)), "meta")
        else:
            impl = config_for("implementer").provider
            ranked = [p for p in ("meta", "gemini", "anthropic", "openai", "fireworks") if p != impl] + [impl]
            provider = next((p for p in ranked if _key_for(p)), ranked[0])
    preset = PROVIDERS.get(provider, {"base_url": "", "key_env": [], "model": ""})
    return ModelConfig(
        role=role,
        provider=provider,
        base_url=os.environ.get(f"ADVERSARY_{R}_BASE_URL", preset["base_url"]).rstrip("/"),
        model=os.environ.get(f"ADVERSARY_{R}_MODEL", preset["model"]),
        api_key=os.environ.get(f"ADVERSARY_{R}_API_KEY") or _key_for(provider),
    )


@dataclass
class Completion:
    text: str
    request_hash: str
    cached: bool
    model: str
    latency: float


def _reasoning_effort(cfg: ModelConfig) -> str | None:
    eff = os.environ.get(f"ADVERSARY_{cfg.role.upper()}_REASONING")
    if eff is None and cfg.provider == "meta":
        eff = "low"  # Muse models are reasoning models; "low" is ~4x faster and leaves budget for the answer
    return eff or None


def chat(role: str, messages: list[dict], temperature: float = 0.0, max_tokens: int = 24000, tag: str = "") -> Completion:
    cfg = config_for(role)
    effort = _reasoning_effort(cfg)
    req = {"provider": cfg.provider, "model": cfg.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    if effort:
        req["reasoning_effort"] = effort
    h = sha256_json(req)
    mode = os.environ.get("ADVERSARY_LLM_MODE", "auto")
    path = CASSETTE_DIR / f"{h}.json"
    if mode in ("auto", "replay") and path.exists():
        data = json.loads(path.read_text())
        return Completion(data["text"], h, True, cfg.model, 0.0)
    if mode == "replay" or (mode == "auto" and not cfg.api_key):
        # Same prompt recorded under another provider/model name (a clone without the recording machine's
        # .env): replay it and report the model that actually answered.
        rec = _find_recorded(req)
        if rec is not None:
            return Completion(rec["text"], rec["hash"], True, rec["model"], 0.0)
    if mode == "replay":
        raise LLMError(f"[{role}] no recorded completion for request {h[:12]} (ADVERSARY_LLM_MODE=replay)")
    if not cfg.api_key:
        raise LLMError(f"[{role}] no API key for provider '{cfg.provider}' (set {PROVIDERS.get(cfg.provider, {}).get('key_env', ['ADVERSARY_' + role.upper() + '_API_KEY'])[0]})")

    t0 = time.monotonic()
    body = {"model": cfg.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    if effort:
        body["reasoning_effort"] = effort
    last_err = None
    for attempt in range(3):
        try:
            r = httpx.post(
                f"{cfg.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {cfg.api_key}", "Content-Type": "application/json"},
                json=body, timeout=180,
            )
            if r.status_code == 400 and "max_tokens" in r.text and "max_completion_tokens" in r.text:
                body["max_completion_tokens"] = body.pop("max_tokens")
                continue
            if r.status_code >= 400:
                raise LLMError(f"[{role}] {cfg.provider} HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            if data["choices"][0].get("finish_reason") == "length":
                raise LLMError(f"[{role}] response truncated at max_tokens={body.get('max_tokens', body.get('max_completion_tokens'))}")
            text = data["choices"][0]["message"]["content"] or ""
            if isinstance(text, list):
                text = "".join(part.get("text", "") for part in text if isinstance(part, dict))
            break
        except (httpx.HTTPError, LLMError, KeyError) as e:
            last_err = e
            if isinstance(e, LLMError) and (("HTTP 4" in str(e) and "429" not in str(e)) or "truncated" in str(e)):
                raise
            time.sleep(1.5 * (attempt + 1))
    else:
        raise LLMError(f"[{role}] request failed after retries: {last_err}")
    if not text.strip():
        raise LLMError(f"[{role}] empty response from {cfg.model}")

    latency = time.monotonic() - t0
    CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"request": req, "text": text, "tag": tag, "latency": latency}, indent=2))
    return Completion(text, h, False, cfg.model, latency)


_CONTENT_INDEX: dict[str, dict] | None = None


def _content_key(req: dict) -> str:
    return sha256_json({k: v for k, v in req.items() if k not in ("provider", "model")})


def _find_recorded(req: dict) -> dict | None:
    """Look a request up in the cassettes by content, ignoring provider/model."""
    global _CONTENT_INDEX
    if _CONTENT_INDEX is None:
        _CONTENT_INDEX = {}
        if CASSETTE_DIR.exists():
            for p in sorted(CASSETTE_DIR.glob("*.json")):
                try:
                    d = json.loads(p.read_text())
                    r = d.get("request") or {}
                    if "messages" in r and "text" in d:
                        _CONTENT_INDEX.setdefault(_content_key(r), {"text": d["text"], "model": r.get("model", ""), "hash": p.stem})
                except (OSError, ValueError):
                    continue
    return _CONTENT_INDEX.get(_content_key(req))


def extract_code(text: str, lang: str = "python") -> str:
    blocks = re.findall(r"```(?:" + lang + r"|py)?\s*\n(.*?)```", text, flags=re.S)
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    m = re.search(r"```(?:" + lang + r"|py)?\s*\n(.*)$", text, flags=re.S)  # unclosed fence
    if m:
        return m.group(1).strip() + "\n"
    return text.strip() + "\n"


def extract_json(text: str) -> dict:
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, flags=re.S)
    candidate = m.group(1) if m else text
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1:
        raise LLMError("model did not return JSON")
    return json.loads(candidate[start:end + 1])
