"""FastAPI HTTP wrapper."""
from __future__ import annotations
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

from .tools import build_tool_registry


class CallRequest(BaseModel):
    name: str
    arguments: dict[str, Any] = {}


app = FastAPI(title="gestnova-shell-mcp HTTP")
_registry = build_tool_registry()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "tools_loaded": str(len(_registry))}


@app.get("/tools")
async def list_tools() -> list[dict[str, Any]]:
    return [{"name": n, "description": s["description"], "input_schema": s["input_schema"]} for n, s in _registry.items()]


@app.post("/call")
async def call_tool(req: CallRequest) -> dict[str, Any]:
    if req.name not in _registry:
        raise HTTPException(status_code=404, detail=f"unknown tool: {req.name}")
    try:
        result = _registry[req.name]["handler"](req.arguments or {})
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "tool": req.name}
    return json.loads(json.dumps(result, default=str))


def main() -> None:
    port = int(os.getenv("PORT", "8017"))
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
