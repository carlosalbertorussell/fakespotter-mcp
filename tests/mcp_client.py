"""
Calls FakeSpotter tools through the public MCP client API.

Every test goes through an in-memory ClientSession connected to the real
``server.mcp`` instance, so arguments are JSON-serialised, validated against
the published input schema and returned as protocol content blocks, exactly
as a real MCP client sees them. Nothing here touches ``mcp._tool_manager``.

This is the single place to adapt when mcp 2 lands (e.g. if the in-memory
helper moves or ``FastMCP`` is renamed); the tests themselves only use
``call_tool`` / ``list_tool_names``.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from mcp.shared.memory import create_connected_server_and_client_session


def _server():
    import server  # src/server.py — registers all 29 tools

    return server.mcp


@dataclass
class ToolResult:
    text: str
    is_error: bool

    def __contains__(self, item: str) -> bool:
        return item in self.text

    @property
    def verdict(self) -> str | None:
        """VERDICT line of a full-mode Forensic Certificate, if present."""
        for line in self.text.splitlines():
            if line.strip().startswith("VERDICT"):
                return line.split(":", 1)[1].strip()
        return None


async def _acall(name: str, arguments: dict[str, Any]) -> ToolResult:
    async with create_connected_server_and_client_session(_server()) as session:
        result = await session.call_tool(name, arguments)
    text = "\n".join(getattr(block, "text", "") for block in result.content)
    return ToolResult(text=text, is_error=bool(result.isError))


async def acall_tool(name: str, **params: Any) -> ToolResult:
    """Async variant of :func:`call_tool`."""
    return await _acall(name, {"params": params})


def call_tool(name: str, **params: Any) -> ToolResult:
    """Call tool ``name``; every FakeSpotter tool takes a single ``params`` object."""
    return asyncio.run(acall_tool(name, **params))


async def _alist() -> list[str]:
    async with create_connected_server_and_client_session(_server()) as session:
        listed = await session.list_tools()
    return sorted(tool.name for tool in listed.tools)


def list_tool_names() -> list[str]:
    return asyncio.run(_alist())
