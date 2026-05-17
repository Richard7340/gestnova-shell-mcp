"""Command whitelist por categoria.

Cada categoria define los binarios permitidos y opcionalmente patrones de
argumentos prohibidos (regex). El binario se verifica como token[0] tras
shlex.split — sin shell expansion ni pipes (modo strict).
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field


@dataclass
class CommandRule:
    binaries: set[str] = field(default_factory=set)
    forbidden_arg_patterns: list[re.Pattern] = field(default_factory=list)
    description: str = ""


COMMAND_CATEGORIES: dict[str, CommandRule] = {
    # Read-only / informational
    "read": CommandRule(
        binaries={"ls", "cat", "head", "tail", "wc", "file", "stat", "find", "tree", "du", "df", "pwd", "echo", "date", "uname", "whoami"},
        forbidden_arg_patterns=[re.compile(r"^-delete$"), re.compile(r"^-exec$")],
        description="Read-only filesystem and system info commands.",
    ),
    # Git read-only
    "git_read": CommandRule(
        binaries={"git"},
        forbidden_arg_patterns=[
            re.compile(r"^(push|pull|fetch|merge|rebase|reset|checkout|switch|branch|tag|clean|gc|filter-branch|stash|cherry-pick|revert|commit|rm|mv|am|format-patch)$"),
        ],
        description="Git inspection only: status, log, diff, show, blame. Never write/push.",
    ),
    # Build / test (deterministic, project-local)
    "build": CommandRule(
        binaries={"npm", "pnpm", "yarn", "uv", "pip", "pytest", "node", "tsc", "vitest", "ruff", "mypy", "black", "make"},
        forbidden_arg_patterns=[
            re.compile(r"^(publish|push)$"),
            re.compile(r"^--registry$"),
        ],
        description="Project build, test, lint commands. No publish.",
    ),
    # Safe Python execution — restricted to known scripts
    "python_safe": CommandRule(
        binaries={"python", "python3"},
        forbidden_arg_patterns=[re.compile(r"^-c$")],
        description="Run python <script>. No -c inline code.",
    ),
    # Finance / accounting CLI tools we own
    "finance_tools": CommandRule(
        binaries={"gestnova-accounting-mcp", "gestnova-accounting-http", "gestnova-filesystem-mcp", "gestnova-filesystem-http", "gestnova-shell-http"},
        description="Our own MCP CLIs.",
    ),
}


FORBIDDEN_GLOBAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"[;&|`$()<>]"),  # any shell metacharacter slipped through
    re.compile(r"\$\{"),
    re.compile(r"\.\./"),
]


def is_allowed(category: str, argv: list[str]) -> tuple[bool, str]:
    """Returns (allowed, reason). reason is empty when allowed."""
    if not argv:
        return False, "empty command"
    rule = COMMAND_CATEGORIES.get(category)
    if rule is None:
        return False, f"unknown category: {category!r} — see listCategories"
    binary = argv[0]
    if binary not in rule.binaries:
        return False, f"binary {binary!r} not allowed in category {category!r} — allowed: {sorted(rule.binaries)}"
    # Check forbidden patterns per-category
    for arg in argv[1:]:
        for pat in rule.forbidden_arg_patterns:
            if pat.search(arg):
                return False, f"forbidden arg pattern in category {category!r}: {arg!r}"
        for pat in FORBIDDEN_GLOBAL_PATTERNS:
            if pat.search(arg):
                return False, f"forbidden shell metacharacter in arg: {arg!r}"
    return True, ""


def categories_listing() -> list[dict]:
    return [
        {"category": k, "binaries": sorted(v.binaries), "description": v.description}
        for k, v in sorted(COMMAND_CATEGORIES.items())
    ]
