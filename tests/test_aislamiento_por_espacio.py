"""
El shell debe darle a cada espacio de trabajo su propio directorio.

Hasta ahora `tenantId` solo servia para el registro de auditoria: todos los
espacios compartian /data/workspace entero. Nadie habia llegado a usarlo (el
volumen estaba vacio y ningun espacio tenia el shell activado), asi que no se
filtro nada; pero en el momento en que se encendiera, cualquier administrador
habria podido leer lo que otro espacio dejase ahi.

Estos tests fijan lo contrario: lo mio es mio, y lo del vecino no se ve.
"""
import tempfile
from pathlib import Path

import pytest

from gestnova_shell.executor import exec_task, carpeta_del_espacio


@pytest.fixture
def raiz(monkeypatch):
    tmp = tempfile.mkdtemp(prefix="shell-aisl-")
    audit = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
    audit.close()
    monkeypatch.setenv("SHELL_ALLOWED_ROOTS", tmp)
    monkeypatch.setenv("SHELL_AUDIT_LOG", audit.name)
    return Path(tmp).resolve()


def test_cada_espacio_tiene_su_carpeta(raiz):
    a = carpeta_del_espacio("empresa-a")
    b = carpeta_del_espacio("empresa-b")
    assert a != b
    assert a.is_dir() and b.is_dir()
    assert a.parent == raiz


def test_sin_cwd_se_trabaja_en_la_carpeta_propia(raiz):
    r = exec_task("read", "pwd", "", tenant_id="empresa-a")
    assert r.ok is True
    assert Path(r.cwd).resolve() == carpeta_del_espacio("empresa-a").resolve()


def test_no_puedo_entrar_en_la_carpeta_del_vecino(raiz):
    vecina = carpeta_del_espacio("empresa-b")
    (vecina / "secreto.txt").write_text("nomina de la empresa B")

    r = exec_task("read", "ls", str(vecina), tenant_id="empresa-a")
    assert r.ok is False
    assert "secreto" not in r.stdout


def test_tampoco_subiendo_por_la_raiz_compartida(raiz):
    # El intento evidente: pedir la raiz comun y listar desde ahi.
    r = exec_task("read", "ls", str(raiz), tenant_id="empresa-a")
    assert r.ok is False


def test_un_nombre_con_puntos_no_escapa(raiz):
    # "../otro" como id de espacio no puede sacarme de la raiz permitida.
    c = carpeta_del_espacio("../empresa-b")
    # Lo unico que importa: sigue colgando de la raiz permitida, no fuera.
    assert c.parent == raiz
    assert ".." not in c.name


def test_sin_espacio_tambien_queda_confinado(raiz):
    # Las llamadas internas sin tenant no pueden quedarse con la raiz entera:
    # seria la puerta trasera que anula todo lo anterior.
    r = exec_task("read", "ls", str(raiz), tenant_id=None)
    assert r.ok is False


def test_el_de_siempre_sigue_funcionando_en_lo_suyo(raiz):
    propia = carpeta_del_espacio("empresa-a")
    (propia / "mio.txt").write_text("mis cosas")
    r = exec_task("read", "ls", str(propia), tenant_id="empresa-a")
    assert r.ok is True
    assert "mio.txt" in r.stdout


def test_las_raices_que_se_anuncian_son_las_que_se_pueden_usar(raiz):
    # Anunciar la raiz comun y luego rechazarla es la peor combinacion: el
    # agente hace justo lo que se le dice y le falla todo sin entender por que.
    from gestnova_shell.executor import list_allowed_roots

    anunciadas = list_allowed_roots("empresa-a")
    assert anunciadas == [str(carpeta_del_espacio("empresa-a"))]

    r = exec_task("read", "ls", anunciadas[0], tenant_id="empresa-a")
    assert r.ok is True


def test_sin_espacio_tambien_se_anuncia_lo_usable(raiz):
    from gestnova_shell.executor import list_allowed_roots

    anunciadas = list_allowed_roots(None)
    r = exec_task("read", "ls", anunciadas[0], tenant_id=None)
    assert r.ok is True
