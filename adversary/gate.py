"""GitHub merge gate.

  adversary run <task> --plant subtle --open-pr   implementer opens a real PR (via a throwaway git worktree)
  adversary gate <pr-number>                      verify the PR head and post a commit status + PR comment

The status context `adversary/verify` can be made a required check in branch protection, so a BLOCK
verdict literally blocks the merge button.

Repo layout: each task lives at playground/<task>/ in the repository (mirroring tasks/<task>/base/).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path

from .hashing import short
from .verdict import Verdict
from .workspace import ROOT, RUNS_DIR, Change, Task, list_tasks, load_task, write_tree

PLAYGROUND = "playground"
CONTEXT = "adversary/verify"


def _run(cmd: list[str], cwd: Path = ROOT, check: bool = True) -> str:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd[:3])} failed: {p.stderr.strip()[:400]}")
    return p.stdout


def repo_slug() -> str:
    return _run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"]).strip()


def open_pr(task: Task, change: Change, title: str, body: str) -> dict:
    """Commit the change under playground/<task>/ on a fresh branch in a temporary worktree, push, open a PR."""
    branch = f"ai/{task.name}-{uuid.uuid4().hex[:6]}"
    wt = RUNS_DIR / ".worktrees" / branch.replace("/", "-")
    _run(["git", "fetch", "-q", "origin", "main"])
    _run(["git", "worktree", "add", "-q", "-b", branch, str(wt), "origin/main"])
    try:
        dest = wt / PLAYGROUND / task.name
        if dest.exists():
            shutil.rmtree(dest)
        write_tree(dest, change.full_tree())
        _run(["git", "add", "-A", PLAYGROUND], cwd=wt)
        _run(["git", "commit", "-q", "-m", f"{title}\n\nOpened by the Adversary implementer agent."], cwd=wt)
        _run(["git", "push", "-q", "-u", "origin", branch], cwd=wt)
        url = _run(["gh", "pr", "create", "--base", "main", "--head", branch, "--title", title, "--body", body], cwd=wt).strip()
    finally:
        _run(["git", "worktree", "remove", "--force", str(wt)], check=False)
    number = int(url.rstrip("/").rsplit("/", 1)[-1])
    return {"branch": branch, "url": url, "number": number}


def ensure_playground(task: Task) -> bool:
    """True if playground/<task>/ exists on origin/main (the PR base must contain the task's base files)."""
    _run(["git", "fetch", "-q", "origin", "main"])
    out = _run(["git", "ls-tree", "--name-only", "origin/main", f"{PLAYGROUND}/{task.name}/"], check=False)
    return bool(out.strip())


def fetch_pr(number: int) -> tuple[Task, Change, dict]:
    info = json.loads(_run(["gh", "pr", "view", str(number), "--json", "number,headRefOid,headRefName,title,url,files"]))
    sha = info["headRefOid"]
    _run(["git", "fetch", "-q", "origin", f"pull/{number}/head:refs/adversary/pr-{number}"])
    touched = {f["path"] for f in info.get("files", [])}
    task = None
    for t in list_tasks():
        if any(p.startswith(f"{PLAYGROUND}/{t.name}/") for p in touched):
            task = t
            break
    if task is None:
        raise RuntimeError(f"PR #{number} touches no playground/<task>/ directory")
    prefix = f"{PLAYGROUND}/{task.name}/"
    names = _run(["git", "ls-tree", "-r", "--name-only", sha, prefix]).split()
    after = {}
    for n in names:
        if n.endswith((".py", ".md", ".txt", ".json", ".ini", ".cfg", ".toml")):
            after[n[len(prefix):]] = _run(["git", "show", f"{sha}:{n}"])
    change = Change(base=task.base, after=after, meta={"source": "github", "pr": number, "sha": sha})
    return task, change, info


def post_status(sha: str, state: str, description: str, target_url: str | None = None) -> None:
    cmd = ["gh", "api", f"repos/{repo_slug()}/statuses/{sha}", "-f", f"state={state}", "-f", f"context={CONTEXT}",
           "-f", f"description={description[:139]}"]
    if target_url:
        cmd += ["-f", f"target_url={target_url}"]
    _run(cmd)


def comment_markdown(v: Verdict, run_dir: Path) -> str:
    block = v.decision == "BLOCK"
    icon = {"pass": "✅", "fail": "⛔", "warn": "⚠️", "skip": "➖", "error": "⛔"}
    lines = [f"## {'⛔ Adversary blocked this merge' if block else '✅ Adversary: safe to merge'}", ""]
    lines += [f"- {r}" for r in v.reasons]
    lines += ["", "| check | result | |", "|---|---|---|"]
    for c in v.checks:
        lines.append(f"| {c.title} | {icon.get(c.status, c.status)} {c.status} | {c.summary.replace('|', '/')[:180]} |")
    ce = next((c for c in v.checks if c.id == "property_tests"), None)
    if ce and ce.details.get("counterexamples"):
        lines += ["", "**Counterexamples** (reproducible with the pinned seed):", "```"]
        lines += [f"{x['test']}: {x['falsifying'] or x['message'][:200]}" for x in ce.details["counterexamples"][:5]]
        lines += ["```"]
    lines += [
        "",
        "<details><summary>Reproducibility</summary>",
        "",
        f"- seed `{v.seed}`, sandbox `{v.environment['sandbox']['kind']}` (network {v.environment['sandbox']['network']}), python `{v.environment['python']}`",
        f"- spec `{short(v.inputs['spec_sha256'])}` · diff `{short(v.inputs['diff_sha256'])}` · pinned tests `{short(v.pinned['verifier_tests_sha256'] or '-')}` · lock `{short(v.environment['lock_sha256'])}`",
        f"- outcome `{v.outcome_sha256}`",
        f"- verdict `{v.verdict_sha256}`",
        f"- `adversary reproduce {run_dir}`",
        "",
        f"Verifier ({v.models['verifier'].get('provider')}/{v.models['verifier'].get('model')}) saw only the spec and the comment-stripped diff. "
        "Implementer reasoning and tests were withheld.",
        "</details>",
    ]
    return "\n".join(lines)


def comment(number: int, body: str) -> None:
    path = RUNS_DIR / f".pr-{number}-comment.md"
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    _run(["gh", "pr", "comment", str(number), "--body-file", str(path)])
