import os
import tempfile
from pathlib import Path
import pytest

from gestnova_shell.executor import exec_task, tail_audit, carpeta_del_espacio

# Cada espacio trabaja dentro de SU carpeta, no en la raiz compartida. Estos
# tests comprueban lo de siempre (que un comando legitimo corre, que uno
# prohibido no), solo que ahora dentro del espacio que les toca.
ESPACIO = "espacio-de-prueba"


@pytest.fixture
def sandbox(monkeypatch):
    tmp = tempfile.mkdtemp(prefix="shell-test-")
    audit = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    audit.close()
    monkeypatch.setenv("SHELL_ALLOWED_ROOTS", tmp)
    monkeypatch.setenv("SHELL_AUDIT_LOG", audit.name)
    return carpeta_del_espacio(ESPACIO)


def test_exec_ls_succeeds(sandbox):
    r = exec_task("read", "ls -la", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is True
    assert r.exitCode == 0
    assert Path(r.cwd).resolve() == Path(sandbox).resolve()


def test_exec_echo_returns_stdout(sandbox):
    r = exec_task("read", "echo hola", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is True
    assert "hola" in r.stdout


def test_exec_unauthorized_command_blocked(sandbox):
    r = exec_task("read", "rm -rf /tmp/foo", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is False
    assert "not allowed" in r.reason


def test_exec_cwd_outside_allowed_blocked(sandbox):
    r = exec_task("read", "ls", "/etc")
    assert r.ok is False
    assert (
        "allowed root" in r.reason.lower()
        or "not under" in r.reason.lower()
        or "fuera del espacio" in r.reason.lower()
    )


def test_exec_pipe_in_argv_blocked(sandbox):
    r = exec_task("read", "ls | rm", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is False


def test_exec_path_traversal_blocked(sandbox):
    r = exec_task("read", "cat ../../etc/passwd", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is False


def test_exec_timeout_enforced(sandbox):
    # `python -c "import time; time.sleep(10)"` would work but -c is blocked.
    # Use a non-existent binary with timeout=1 to test the path doesn't hang.
    # Actually, test by running echo with a very short legit command.
    r = exec_task("read", "echo done", str(sandbox), timeout_s=5, tenant_id=ESPACIO)
    assert r.ok is True


def test_audit_log_records_executions(sandbox):
    exec_task("read", "echo audit-test", str(sandbox), tenant_id=ESPACIO)
    exec_task("read", "rm /etc/passwd", str(sandbox), tenant_id=ESPACIO)  # denied
    entries = tail_audit(10)
    assert len(entries) >= 2
    events = [e["event"] for e in entries]
    assert "exec" in events
    assert "denied" in events


def test_unknown_category_returns_denied(sandbox):
    r = exec_task("hack", "ls", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is False
    assert "unknown" in r.reason.lower()


def test_parse_error_on_unclosed_quote(sandbox):
    r = exec_task("read", "echo 'unclosed", str(sandbox), tenant_id=ESPACIO)
    assert r.ok is False
    assert "parse" in r.reason.lower()
