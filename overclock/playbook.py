"""The playbook: a versioned, append-only list of optimization rules, plus a decision ledger.

Every candidate rule gets its own version file (v001.json, v002.json, ...). Files are immutable.
`CURRENT` points at the last *accepted* version. A rejected candidate stays on disk with
status "rolled_back" so the history shows exactly what was tried and thrown away.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

PLAYBOOK_DIR = Path("playbook")


@dataclass
class Rule:
    id: str
    text: str
    learned_from: str
    version_added: int
    heldout_before: float | None = None
    heldout_after: float | None = None


@dataclass
class Playbook:
    version: int = 0
    rules: list[Rule] = field(default_factory=list)
    status: str = "accepted"          # accepted | candidate | rolled_back
    parent: int | None = None

    # ---- prompt rendering -------------------------------------------------
    def render(self) -> str:
        if not self.rules:
            return "(the playbook is empty: no rules have been learned yet)"
        return "\n".join(f"{i + 1}. {r.text}" for i, r in enumerate(self.rules))

    def with_rule(self, text: str, learned_from: str, next_version: int) -> "Playbook":
        rid = f"R{len(self.rules) + 1:02d}"
        return Playbook(
            version=next_version,
            rules=[*self.rules, Rule(rid, text, learned_from, next_version)],
            status="candidate",
            parent=self.version,
        )

    # ---- persistence ------------------------------------------------------
    def to_dict(self) -> dict:
        return {"version": self.version, "status": self.status, "parent": self.parent,
                "rules": [asdict(r) for r in self.rules]}

    @classmethod
    def from_dict(cls, d: dict) -> "Playbook":
        return cls(version=d["version"], status=d.get("status", "accepted"), parent=d.get("parent"),
                   rules=[Rule(**r) for r in d["rules"]])

    def save(self, directory: Path = PLAYBOOK_DIR) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"v{self.version:03d}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        return path


def _current_path(directory: Path) -> Path:
    return directory / "CURRENT"


def latest_version_number(directory: Path = PLAYBOOK_DIR) -> int:
    nums = [int(p.stem[1:]) for p in directory.glob("v*.json")] if directory.exists() else []
    return max(nums, default=0)


def load_current(directory: Path = PLAYBOOK_DIR) -> Playbook:
    cur = _current_path(directory)
    if not cur.exists():
        return Playbook()
    v = int(cur.read_text().strip())
    return Playbook.from_dict(json.loads((directory / f"v{v:03d}.json").read_text()))


def accept(candidate: Playbook, directory: Path = PLAYBOOK_DIR) -> Playbook:
    candidate.status = "accepted"
    candidate.save(directory)
    _current_path(directory).write_text(str(candidate.version))
    return candidate


def rollback(candidate: Playbook, directory: Path = PLAYBOOK_DIR) -> None:
    candidate.status = "rolled_back"
    candidate.save(directory)        # keep the evidence; CURRENT is untouched


def reset(directory: Path = PLAYBOOK_DIR) -> None:
    if directory.exists():
        for p in directory.glob("v*.json"):
            p.unlink()
        for name in ("CURRENT", "ledger.jsonl"):
            (directory / name).unlink(missing_ok=True)
    directory.mkdir(parents=True, exist_ok=True)
    Playbook().save(directory)


# ---- ledger -------------------------------------------------------------------
def log(entry: dict, directory: Path = PLAYBOOK_DIR) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    entry = {"ts": time.time(), **entry}
    with (directory / "ledger.jsonl").open("a") as f:
        f.write(json.dumps(entry) + "\n")


def read_ledger(directory: Path = PLAYBOOK_DIR) -> list[dict]:
    p = directory / "ledger.jsonl"
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
