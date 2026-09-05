"""Sandboxed shell executor with audit logging.

Sin shell=True, sin pipes, sin redireccion: subprocess.run con argv parseado.
"""
from __future__ import annotations
import json
import os
import re
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


# Un id de espacio viene del backend (un cuid), pero de aqui no se fia nadie:
# si se usa tal cual para construir una ruta, un "../otro" saldria de la raiz.
_NOMBRE_SEGURO = re.compile(r"[^A-Za-z0-9_-]")

# Las llamadas internas que no traen espacio tampoco pueden quedarse con la
# raiz entera: seria la puerta de atras que anula todo el aislamiento.
CARPETA_SIN_ESPACIO = "_sin-espacio"


# Rango por encima de los usuarios del sistema. Los uid se reparten en orden y
# se guardan: si cambiaran entre reinicios, cada espacio perderia el acceso a
# sus propios ficheros.
UID_BASE = 20000


def _mapa_de_uids() -> Path:
    return Path(os.getenv("SHELL_UID_MAP", str(_audit_path().parent / "uids.json")))


def uid_del_espacio(tenant_id: str | None) -> int:
    """El usuario del sistema con el que corre este espacio.

    La barrera de verdad la pone el sistema de ficheros. Confinar el directorio
    de trabajo no basta: un comando puede nombrar la ruta absoluta del vecino y
    leerla igual. Con un uid propio y la carpeta en 0700, el nucleo lo impide
    diga lo que diga el comando.
    """
    nombre = _NOMBRE_SEGURO.sub("_", (tenant_id or "").strip()) or CARPETA_SIN_ESPACIO
    ruta = _mapa_de_uids()
    try:
        mapa = json.loads(ruta.read_text()) if ruta.exists() else {}
    except (json.JSONDecodeError, OSError):
        mapa = {}
    if nombre in mapa:
        return int(mapa[nombre])
    usados = {int(v) for v in mapa.values()}
    uid = UID_BASE
    while uid in usados:
        uid += 1
    mapa[nombre] = uid
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_suffix(".tmp")
    tmp.write_text(json.dumps(mapa))
    tmp.replace(ruta)  # atomico: dos procesos a la vez no dejan el mapa a medias
    return uid


def carpeta_del_espacio(tenant_id: str | None) -> Path:
    """El directorio propio de un espacio, creado si aun no existe.

    Cada espacio trabaja SOLO dentro del suyo. Antes todos compartian la raiz:
    `tenant_id` solo se escribia en la auditoria, asi que cualquier
    administrador podia leer lo que otro espacio hubiera dejado ahi.
    """
    raices = _allowed_roots()
    if not raices:
        raise RuntimeError("no SHELL_ALLOWED_ROOTS configured and default not present")
    nombre = _NOMBRE_SEGURO.sub("_", (tenant_id or "").strip()) or CARPETA_SIN_ESPACIO
    destino = (raices[0] / nombre).resolve()
    # Doble red: aunque el saneado fallase, la ruta tiene que caer dentro.
    if raices[0] not in destino.parents:
        destino = raices[0] / CARPETA_SIN_ESPACIO
    destino.mkdir(parents=True, exist_ok=True)
    # Privada de su dueno: es esto, y no una comprobacion nuestra sobre el
    # texto del comando, lo que impide que el vecino la lea.
    try:
        os.chmod(destino, 0o700)
        if os.geteuid() == 0:
            uid = uid_del_espacio(tenant_id)
            os.chown(destino, uid, uid)
    except OSError:
        pass
    return destino


def _resolve_cwd(cwd: str, tenant_id: str | None = None) -> tuple[Path | None, str]:
    try:
        propia = carpeta_del_espacio(tenant_id)
    except RuntimeError as exc:
        return None, str(exc)

    # Sin cwd, se trabaja en la carpeta propia: es lo que espera quien llama
    # sin saber nada de rutas.
    if not (cwd or "").strip():
        return propia, ""

    p = Path(cwd).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        return None, f"cwd does not exist or is not a directory: {cwd!r}"

    # La raiz permitida de este espacio es SU carpeta, no la raiz comun: pedir
    # la raiz comun (o la carpeta del vecino) se rechaza igual.
    if p != propia and propia not in p.parents:
        return None, "cwd fuera del espacio de trabajo propio"
    return p, ""


def _append_audit(record: dict) -> None:
    path = _audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record_out = {"ts": datetime.utcnow().isoformat() + "Z", **record}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record_out, default=str) + "\n")
    # El registro guarda el comando Y el stdout de cada espacio, y vive en un
    # volumen cuya ruta cualquiera puede nombrar: en 0644 lo leia el vecino.
    # Solo el proceso que lo escribe.
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass


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

    resolved_cwd, cwd_reason = _resolve_cwd(cwd, tenant_id)
    if resolved_cwd is None:
        result = ExecResult(ok=False, exitCode=None, stdout="", stderr="", durationMs=0, truncated=False, cwd=cwd, argv=argv, category=category, reason=cwd_reason)
        _append_audit({"event": "denied_cwd", "tenant": tenant_id, **asdict(result)})
        return result

    start = time.monotonic()
    try:
        # Como root, el comando se ejecuta con el usuario del espacio: asi el
        # nucleo aplica los permisos y da igual que ruta absoluta se nombre.
        # Sin root (desarrollo) no se puede cambiar de usuario y solo queda el
        # confinamiento del cwd, que NO basta por si solo.
        extra: dict = {}
        if os.geteuid() == 0:
            uid = uid_del_espacio(tenant_id)
            # HOME apunta a su carpeta: el usuario del espacio no puede escribir
            # en /root, y herramientas como npm o uv fallarian ahi con un error
            # de permisos que no dice nada de lo que pasa de verdad.
            entorno = {**os.environ, "HOME": str(resolved_cwd)}
            extra = {"user": uid, "group": uid, "env": entorno}
        proc = subprocess.run(
            argv,
            cwd=str(resolved_cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            shell=False,
            **extra,
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


def tail_audit(n: int = 50, tenant_id: str | None = None) -> list[dict]:
    """La cola de auditoria DE UN ESPACIO.

    Devolvia la cola global sin filtrar: preguntar "que hice antes" enseñaba
    los comandos y la salida de los demas. Se filtra siempre; sin espacio, solo
    se ven las entradas que tampoco tenian espacio.
    """
    path = _audit_path()
    if not path.exists():
        return []
    # Se filtra ANTES de recortar: quedarse con las ultimas n lineas y filtrar
    # despues devolveria casi nada en cuanto otro espacio estuviera activo.
    with path.open("r", encoding="utf-8") as f:
        lines = f.readlines()
    out: list[dict] = []
    for line in lines:
        try:
            entrada = json.loads(line)
        except Exception:
            continue
        if entrada.get("tenant") != tenant_id:
            continue
        out.append(entrada)
    return out[-n:]


def list_allowed_roots(tenant_id: str | None = None) -> list[str]:
    """El unico directorio en el que este espacio puede trabajar.

    Antes devolvia la raiz comun. Anunciar una raiz que luego se rechaza es la
    peor combinacion posible: el agente hace exactamente lo que se le dice y le
    falla todo sin entender por que.
    """
    return [str(carpeta_del_espacio(tenant_id))]
