"""
El shell debe darle a cada espacio de trabajo su propio directorio.

Hasta ahora `tenantId` solo servia para el registro de auditoria: todos los
espacios compartian /data/workspace entero. Nadie habia llegado a usarlo (el
volumen estaba vacio y ningun espacio tenia el shell activado), asi que no se
filtro nada; pero en el momento en que se encendiera, cualquier administrador
habria podido leer lo que otro espacio dejase ahi.

Estos tests fijan lo contrario: lo mio es mio, y lo del vecino no se ve.
"""
import json
import tempfile
from pathlib import Path

import pytest

from gestnova_shell.executor import exec_task, carpeta_del_espacio


@pytest.fixture
def raiz(monkeypatch):
    tmp = tempfile.mkdtemp(prefix="shell-aisl-")
    # El registro va en SU carpeta, como en el contenedor. Si cayera suelto en
    # el temporal del sistema, este test estaria comprobando los permisos de
    # /tmp en vez de los nuestros.
    dir_audit = tempfile.mkdtemp(prefix="shell-audit-")
    monkeypatch.setenv("SHELL_ALLOWED_ROOTS", tmp)
    monkeypatch.setenv("SHELL_AUDIT_LOG", str(Path(dir_audit) / "shell-audit.jsonl"))
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


# ── Lo que el cwd NO protege ────────────────────────────────────────────────
# Confinar el directorio de trabajo no impide nombrar una ruta absoluta: el
# primer intento dejaba pasar `cat /data/workspace/otro/secreto.txt` desde la
# carpeta propia. La barrera tiene que ponerla el sistema de ficheros, no una
# comprobacion nuestra sobre el texto del comando.
import os

from gestnova_shell.executor import uid_del_espacio


def test_cada_espacio_tiene_un_uid_propio_y_estable(raiz):
    a1 = uid_del_espacio("empresa-a")
    a2 = uid_del_espacio("empresa-a")
    b = uid_del_espacio("empresa-b")
    assert a1 == a2, "el mismo espacio no puede cambiar de uid entre llamadas"
    assert a1 != b, "dos espacios distintos no pueden compartir uid"
    assert a1 >= 20000, "fuera del rango de usuarios del sistema"


def test_la_carpeta_es_privada_de_su_espacio(raiz):
    c = carpeta_del_espacio("empresa-a")
    modo = oct(c.stat().st_mode)[-3:]
    assert modo == "700", f"la carpeta deberia ser privada, es {modo}"


@pytest.mark.skipif(os.geteuid() != 0, reason="cambiar de usuario requiere root")
def test_no_puedo_leer_el_fichero_del_vecino_ni_por_ruta_absoluta(raiz):
    vecina = carpeta_del_espacio("empresa-b")
    (vecina / "secreto.txt").write_text("nomina de la empresa B")

    r = exec_task("read", f"cat {vecina}/secreto.txt", "", tenant_id="empresa-a")
    assert r.ok is False
    assert "nomina" not in r.stdout


# ── El registro de auditoria tambien es de todos ────────────────────────────
# Guarda el comando Y el stdout de cada espacio. Se quedaba en 0644 dentro de
# un volumen que los inquilinos pueden nombrar, y `tailAudit` devolvia la cola
# global sin filtrar: dos formas distintas de leer lo que hace el vecino.

def test_el_registro_no_lo_puede_leer_un_inquilino(raiz):
    from gestnova_shell.executor import _audit_path

    # Se parte del caso REAL: en el contenedor el fichero estaba en 0644. Si el
    # test empezara con los permisos que ya pone tempfile (0600), pasaria sin
    # que el codigo hiciera nada.
    registro = _audit_path()
    registro.parent.mkdir(parents=True, exist_ok=True)
    registro.touch()
    os.chmod(registro.parent, 0o755)
    os.chmod(registro, 0o644)

    exec_task("read", "echo hola", "", tenant_id="empresa-a")

    assert oct(registro.stat().st_mode)[-3:] == "600", "el registro debe ser solo del proceso"
    assert oct(registro.parent.stat().st_mode)[-3:] == "700", "y su carpeta tambien"


def test_la_cola_de_auditoria_solo_muestra_lo_propio(raiz):
    from gestnova_shell.executor import tail_audit

    exec_task("read", "echo de-la-a", "", tenant_id="empresa-a")
    exec_task("read", "echo de-la-b", "", tenant_id="empresa-b")

    de_a = tail_audit(50, tenant_id="empresa-a")
    assert de_a, "deberia ver lo suyo"
    assert all(e["tenant"] == "empresa-a" for e in de_a)
    assert "de-la-b" not in json.dumps(de_a)


def test_sin_espacio_no_se_ve_lo_de_los_demas(raiz):
    from gestnova_shell.executor import tail_audit

    exec_task("read", "echo de-la-a", "", tenant_id="empresa-a")
    entradas = tail_audit(50, tenant_id=None)
    assert "de-la-a" not in json.dumps(entradas)
