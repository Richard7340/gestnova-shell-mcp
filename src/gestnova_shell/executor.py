"""Sandboxed shell executor with audit logging.

Sin shell=True, sin pipes, sin redireccion: subprocess.run con argv parseado.
"""
from __future__ import annotations
import json
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from .whitelist import is_allowed


DEFAULT_ROOTS = [
    Path.home() / "Documents" / "New project",
]
DEFAULT_AUDIT_LOG = Path.home() / ".gestnova-shell" / "audit.jsonl"
MAX_STDOUT_BYTES = 200_000
DEFAULT_TIMEOUT_S = 60
MAX_TIMEOUT_S = 300


@dataclass
class ExecResult:
    ok: bool
    exitCode: int | None
    stdout: str
    stderr: str
    durationMs: int
    truncated: bool
    cwd: str
    argv: list[str]
    category: str
    reason: str = ""


def _allowed_roots() -> list[Path]:
    env_val = os.getenv("SHELL_ALLOWED_ROOTS")
    if not env_val:
        return [r.resolve() for r in DEFAULT_ROOTS if r.exists()]
    return [Path(p).expanduser().resolve() for p in env_val.split(":") if p]


def _audit_path() -> Path:
    return Path(os.getenv("SHELL_AUDIT_LOG", str(DEFAULT_AUDIT_LOG))).expanduser()


def _resolve_cwd(cwd: str) -> tuple[Path | None, str]:
    p = Path(cwd).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        return None, f"cwd does not exist or is not a directory: {cwd!r}"
    allowed = _allowed_roots()
    if not allowed:
        return None, "no SHELL_ALLOWED_ROOTS configured and default not present"
    for root in allowed:
        try:
            p.relative_to(root)
            return p, ""
        except ValueError:
            continue
    return None, f"cwd not under any allowed root. Allowed: {[str(r) for r in allowed]}"


def _append_audit(record: dict) -> None:
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record_out = {"ts": datetime.utcnow().isoformat() + "Z", **record}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record_out, default=str) + "\n")


def exec_task(category: str, command: str, cwd: str, timeout_s: int = DEFAULT_TIMEOUT_S, tenant_id: str | None = None) -> ExecResult:
    timeout_s = max(1, min(timeout_s, MAX_TIMEOUT_S))
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        return ExecResult(ok=False, exitCode=None, stdout="", stderr="", durationMs=0, truncated=False, cwd=cwd, argv=[], category=category, reason=f"parse error: {exc}")

    allowed, reason = is_allowed(category, argv)
    if not allowed:
        result = ExecResult(ok=False, exitCode=None, stdout="", stderr="", durationMs=0, truncated=False, cwd=cwd, argv=argv, category=category, reason=reason)
        _append_audit({"event": "denied", "tenant": tenant_id, **asdict(result)})
        return result

    resolved_cwd, cwd_reason = _resolve_cwd(cwd)
    if resolved_cwd is None:
        result = ExecResult(ok=False, exitCode=None, stdout="", stderr="", durationMs=0, truncated=False, cwd=cwd, argv=argv, category=category, reason=cwd_reason)
        _append_audit({"event": "denied_cwd", "tenant": tenant_id, **asdict(result)})
        return result

    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(resolved_cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            shell=False,
        )
        duration_ms = int((time.monotonic() - start) * 1000)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        truncated = False
        if len(stdout) > MAX_STDOUT_BYTES:
            stdout = stdout[:MAX_STDOUT_BYTES]
            truncated = True
        result = ExecResult(
            ok=proc.returncode == 0,
            exitCode=proc.returncode,
            stdout=stdout,
            stderr=stderr[:50_000],
            durationMs=duration_ms,
            truncated=truncated,
            cwd=str(resolved_cwd),
            argv=argv,
            category=category,
        )
    except subprocess.TimeoutExpired:
        duration_ms = int((time.monotonic() - start) * 1000)
        result = ExecResult(ok=False, exitCode=None, stdout="", stderr=f"timeout after {timeout_s}s", durationMs=duration_ms, truncated=False, cwd=str(resolved_cwd), argv=argv, category=category, reason="timeout")
    except FileNotFoundError as exc:
        result = ExecResult(ok=False, exitCode=None, stdout="", stderr=str(exc), durationMs=0, truncated=False, cwd=str(resolved_cwd), argv=argv, category=category, reason=f"binary not found: {argv[0]}")

    _append_audit({"event": "exec", "tenant": tenant_id, **asdict(result)})
    return result


def tail_audit(n: int = 50) -> list[dict]:
    path = _audit_path()
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    out: list[dict] = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def list_allowed_roots() -> list[str]:
    return [str(p) for p in _allowed_roots()]
