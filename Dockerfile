# Plan 35 — shell-mcp (sandboxed shell) Docker image
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_SYSTEM_PYTHON=1 \
    PORT=8017 \
    SHELL_ALLOWED_ROOTS=/data/workspace \
    SHELL_AUDIT_LOG=/data/audit/shell-audit.jsonl

WORKDIR /app

# Tools commonly needed by whitelisted shell categories
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl jq tree \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
RUN uv pip install --system .

COPY src ./src

RUN mkdir -p /data/workspace /data/audit
VOLUME /data/workspace
VOLUME /data/audit

EXPOSE 8017
CMD ["gestnova-shell-http"]
