"""MCP tool registry for gestnova-shell."""
from __future__ import annotations
from dataclasses import asdict
from typing import Any

from .executor import exec_task, list_allowed_roots, tail_audit
from .whitelist import categories_listing


def build_tool_registry() -> dict[str, dict]:
    def t_exec(args: dict) -> dict:
        result = exec_task(
            category=args["category"],
            command=args["command"],
            cwd=args["cwd"],
            timeout_s=int(args.get("timeoutSeconds", 60)),
            tenant_id=args.get("tenantId"),
        )
        return asdict(result)

    def t_list_categories(_args: dict) -> dict:
        return {"categories": categories_listing()}

    def t_list_roots(args: dict) -> dict:
        return {"roots": list_allowed_roots(args.get("tenantId"))}

    def t_tail_audit(args: dict) -> dict:
        return {"entries": tail_audit(int(args.get("n", 50)), args.get("tenantId"))}

    return {
        "execTask": {
            "description": "Ejecuta un comando shell SANDBOXED. El comando debe estar en la whitelist de la categoría dada (read/git_read/build/python_safe/finance_tools). cwd debe estar dentro de las raíces permitidas. Sin pipes/redirect/shell-metacharacters. Devuelve stdout/stderr/exitCode + métricas + flag truncated.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "category": {"type": "string", "description": "Categoría: read, git_read, build, python_safe, finance_tools"},
                    "command": {"type": "string", "description": "Comando completo (será parseado con shlex.split, sin shell)"},
                    "cwd": {"type": "string", "description": "Working directory absoluto, dentro del directorio de TU espacio (ver listAllowedRoots). Vacio = tu directorio"},
                    "timeoutSeconds": {"type": "integer", "description": "Timeout en segundos (1-300, default 60)"},
                    "tenantId": {"type": "string", "description": "ID del espacio de trabajo: determina en que directorio se ejecuta y queda en la auditoria"},
                },
                "required": ["category", "command", "cwd"],
            },
            "handler": t_exec,
        },
        "listCategories": {
            "description": "Lista las categorías de comandos permitidas y qué binarios incluye cada una.",
            "input_schema": {"type": "object", "properties": {}},
            "handler": t_list_categories,
        },
        "listAllowedRoots": {
            "description": "Devuelve el directorio de trabajo de tu espacio: el unico cwd valido para execTask.",
            "input_schema": {
                "type": "object",
                "properties": {"tenantId": {"type": "string", "description": "ID del espacio de trabajo"}},
            },
            "handler": t_list_roots,
        },
        "tailAudit": {
            "description": "Devuelve las últimas N entradas del audit log DE TU ESPACIO (eventos exec/denied/denied_cwd).",
            "input_schema": {
                "type": "object",
                "properties": {
                    "n": {"type": "integer", "default": 50},
                    "tenantId": {"type": "string", "description": "ID del espacio de trabajo"},
                },
            },
            "handler": t_tail_audit,
        },
    }
