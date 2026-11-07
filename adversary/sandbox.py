"""Sandboxed command execution.

Order of preference:
  1. docker   - `--network none`, read-only rootfs, pinned image digest, cpu/mem/pids limits
  2. seatbelt - macOS sandbox-exec: network denied, writes confined to the workspace
  3. local    - plain subprocess with timeout (flagged as NOT isolated in the verdict)

Every run records which isolation was used, so a verdict states how it was produced.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .hashing import sha256_text

DOCKER_IMAGE = os.environ.get("ADVERSARY_DOCKER_IMAGE", "adversary-sandbox:latest")

SEATBELT_PROFILE = """(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath "{workdir}") (literal "/dev/null") (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/tty") (literal "/dev/dtracehelper"))
"""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


@dataclass
class Sandbox:
    kind: str  # docker | seatbelt | local
    python: str = sys.executable
    image_digest: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def isolated(self) -> bool:
        return self.kind in ("docker", "seatbelt")

    def profile_hash(self) -> str:
        if self.kind == "seatbelt":
            return sha256_text(SEATBELT_PROFILE)
        if self.kind == "docker":
            return self.image_digest or "unknown"
        return "none"

    def describe(self) -> dict:
        return {
            "kind": self.kind,
            "isolated": self.isolated,
            "profile_hash": self.profile_hash(),
            "image_digest": self.image_digest,
            "network": "denied" if self.isolated else "allowed",
            "notes": self.notes,
        }

    def run(self, args: list[str], cwd: Path, timeout: float = 60.0, env: dict | None = None) -> RunResult:
        """Run `python <args...>` inside the sandbox with cwd as the only writable dir."""
        cwd = Path(os.path.realpath(cwd))
        (cwd / ".tmp").mkdir(exist_ok=True)
        base_env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(cwd),
            "TMPDIR": str(cwd / ".tmp"),
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(cwd),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        if env:
            base_env.update(env)

        if self.kind == "docker":
            cmd = [
                "docker", "run", "--rm", "--network", "none", "--read-only",
                "--tmpfs", "/tmp", "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
                "-v", f"{cwd}:/work", "-w", "/work",
                *[x for k, v in base_env.items() if k not in ("PATH", "HOME", "TMPDIR", "PYTHONPATH") for x in ("-e", f"{k}={v}")],
                "-e", "PYTHONPATH=/work", "-e", "HOME=/work", "-e", "TMPDIR=/work/.tmp",
                DOCKER_IMAGE, "python", *args,
            ]
            run_env = None
        elif self.kind == "seatbelt":
            profile = cwd / ".tmp" / "adversary.sb"
            profile.write_text(SEATBELT_PROFILE.format(workdir=str(cwd)))
            cmd = ["/usr/bin/sandbox-exec", "-f", str(profile), self.python, *args]
            run_env = base_env
        else:
            cmd = [self.python, *args]
            run_env = base_env

        t0 = time.monotonic()
        try:
            p = subprocess.run(cmd, cwd=cwd, env=run_env, capture_output=True, text=True, timeout=timeout)
            return RunResult(p.returncode, p.stdout, p.stderr, time.monotonic() - t0)
        except subprocess.TimeoutExpired as e:
            out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
            return RunResult(-9, out, err, time.monotonic() - t0, timed_out=True)


def detect_sandbox(prefer: str | None = None) -> Sandbox:
    prefer = prefer or os.environ.get("ADVERSARY_SANDBOX")
    if prefer in (None, "docker") and shutil.which("docker"):
        try:
            digest = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", DOCKER_IMAGE],
                capture_output=True, text=True, timeout=10,
            )
            if digest.returncode == 0:
                return Sandbox("docker", python="python", image_digest=digest.stdout.strip())
        except Exception:
            pass
        if prefer == "docker":
            raise RuntimeError(f"docker image {DOCKER_IMAGE} not found; build with docker/Dockerfile")
    if prefer in (None, "seatbelt") and platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").exists():
        return Sandbox("seatbelt")
    sb = Sandbox("local")
    sb.notes.append("no isolation available: tests ran as a plain subprocess")
    return sb
