"""Verdict ledger: MongoDB when MONGODB_URI is set, otherwise an append-only JSONL file."""
from __future__ import annotations

import json
import os

from .workspace import RUNS_DIR


def record(verdict_dict: dict) -> str:
    uri = os.environ.get("MONGODB_URI")
    if uri:
        try:
            from pymongo import MongoClient
            client = MongoClient(uri, serverSelectionTimeoutMS=4000)
            coll = client[os.environ.get("ADVERSARY_MONGO_DB", "adversary")]["verdicts"]
            coll.update_one({"verdict_sha256": verdict_dict["verdict_sha256"]}, {"$set": verdict_dict}, upsert=True)
            return "mongodb"
        except Exception as e:  # ledger must never break a verdict
            print(f"[adversary] mongodb unavailable ({e}); falling back to jsonl")
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RUNS_DIR / "ledger.jsonl", "a") as f:
        f.write(json.dumps({k: verdict_dict[k] for k in ("run_id", "task", "decision", "verdict_sha256", "outcome_sha256", "created_at")}) + "\n")
    return "jsonl"
