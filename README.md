# gestnova-shell-mcp

MCP server que da a Ian (Gestnova) capacidad de **ejecutar comandos shell sandboxed**
con whitelist por categoría, límite de tiempo/output, cwd allowed-list y audit log
de TODO lo que se ejecuta.

## Seguridad por capas

1. **Comando whitelist** — sólo comandos en `command_whitelist.py` se permiten
   (categorías: read, build, git_read, finance_tools, python_safe).
2. **cwd allowed-list** — `cwd` debe estar bajo una de las raíces permitidas
   (env `SHELL_ALLOWED_ROOTS`, default `~/Documents/New project`).
3. **Sin shell=True real** — `subprocess.run` con `shell=False`, args parseados
   por `shlex.split` y validados.
4. **Hard limits** — timeout 60s default (max 300s), stdout truncado a 200KB,
   bloqueo de pipes y `>` por defecto (modo strict).
5. **Audit log** — JSONL append-only en `SHELL_AUDIT_LOG`
   (default `~/.gestnova-shell/audit.jsonl`).

## Tools

- `execTask` — ejecuta un comando whitelisted en un cwd permitido
- `listCategories` — qué categorías de comandos existen y qué incluye cada una
- `listAllowedRoots` — qué directorios pueden usarse como cwd
- `tailAudit` — devuelve las últimas N entradas del audit log

## Quick start

```bash
uv sync --extra dev
uv run pytest
uv run gestnova-shell-http   # HTTP :8017
```

## Env

- `SHELL_ALLOWED_ROOTS` — rutas separadas por `:` permitidas como cwd
- `SHELL_AUDIT_LOG` — path al audit jsonl
- `PORT` — HTTP port (default 8017)
