"""Minimal OpenAI-compatible chat client with role-separated config and a record/replay cassette.

Roles are configured independently so the implementer and the verifier can (and by default
should) run on *different model families* - the verifier must not share the implementer's
blind spots.

  ADVERSARY_IMPLEMENTER_PROVIDER=meta      (default)  -> Meta Model API, muse-spark
  ADVERSARY_VERIFIER_PROVIDER=gemini|subq|meta|...    -> first one with a key, preferring != implementer

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
    "subq": {"base_url": "https://api.subq.ai/v1", "key_env": ["SUBQ_API_KEY"], "model": "subq-snap-1.1"},
    "fireworks": {"base_url": "https://api.fireworks.ai/inference/v1", "key_env": ["FIREWORKS_API_KEY"], "model": "accounts/fireworks/models/qwen3-coder-480b-a35b-instruct"},
    "openai": {"base_url": "https://api.openai.com/v1", "key_env": ["OPENAI_API_KEY"], "model": "gpt-4.1"},
    "anthropic": {"base_url": "https://api.anthropic.com/v1", "key_env": ["ANTHROPIC_API_KEY"], "model": "claude-sonnet-5-5"},
}


class LLMError(RuntimeError):
    pass


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            m = re.match(r"\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$", line)
            if m and m.group(1) not in os.environ:
                os.environ[m.group(1)] = m.group(2).strip().strip('"').strip("'")


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
            provider = "meta"
        else:
            impl = os.environ.get("ADVERSARY_IMPLEMENTER_PROVIDER", "meta")
            ranked = [p for p in ("gemini", "subq", "anthropic", "openai", "fireworks", "meta") if p != impl] + [impl]
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


def chat(role: str, messages: list[dict], temperature: float = 0.0, max_tokens: int = 8192, tag: str = "") -> Completion:
    cfg = config_for(role)
    req = {"provider": cfg.provider, "model": cfg.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    h = sha256_json(req)
    mode = os.environ.get("ADVERSARY_LLM_MODE", "auto")
    path = CASSETTE_DIR / f"{h}.json"
    if mode in ("auto", "replay") and path.exists():
        data = json.loads(path.read_text())
        return Completion(data["text"], h, True, cfg.model, 0.0)
    if mode == "replay":
        raise LLMError(f"[{role}] no recorded completion for request {h[:12]} (ADVERSARY_LLM_MODE=replay)")
    if not cfg.api_key:
        raise LLMError(f"[{role}] no API key for provider '{cfg.provider}' (set {PROVIDERS.get(cfg.provider, {}).get('key_env', ['ADVERSARY_' + role.upper() + '_API_KEY'])[0]})")

    t0 = time.monotonic()
    body = {"model": cfg.model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
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
            text = data["choices"][0]["message"]["content"] or ""
            if isinstance(text, list):
                text = "".join(part.get("text", "") for part in text if isinstance(part, dict))
            break
        except (httpx.HTTPError, LLMError, KeyError) as e:
            last_err = e
            if isinstance(e, LLMError) and "HTTP 4" in str(e) and "429" not in str(e):
                raise
            time.sleep(1.5 * (attempt + 1))
    else:
        raise LLMError(f"[{role}] request failed after retries: {last_err}")

    latency = time.monotonic() - t0
    CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"request": req, "text": text, "tag": tag, "latency": latency}, indent=2))
    return Completion(text, h, False, cfg.model, latency)


def extract_code(text: str, lang: str = "python") -> str:
    blocks = re.findall(r"```(?:" + lang + r"|py)?\s*\n(.*?)```", text, flags=re.S)
    if blocks:
        return max(blocks, key=len).strip() + "\n"
    return text.strip() + "\n"


def extract_json(text: str) -> dict:
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, flags=re.S)
    candidate = m.group(1) if m else text
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end == -1:
        raise LLMError("model did not return JSON")
    return json.loads(candidate[start:end + 1])
