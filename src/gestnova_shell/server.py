"""MCP stdio server for gestnova-shell."""
import asyncio
import json
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from .tools import build_tool_registry


def _build_app() -> tuple[Server, dict[str, dict]]:
    registry = build_tool_registry()
    app: Server = Server("gestnova-shell")

    @app.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
    async def _list_tools() -> list[Tool]:
        return [Tool(name=name, description=spec["description"], inputSchema=spec["input_schema"]) for name, spec in registry.items()]

    @app.call_tool()  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
        if name not in registry:
            return [TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]
        try:
            result = registry[name]["handler"](arguments or {})
        except Exception as exc:  # noqa: BLE001
            return [TextContent(type="text", text=json.dumps({"error": str(exc), "tool": name}))]
        return [TextContent(type="text", text=json.dumps(result, default=str))]

    return app, registry


async def _run_stdio() -> None:
    app, _ = _build_app()
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


def main() -> None:
    asyncio.run(_run_stdio())


if __name__ == "__main__":
    main()
