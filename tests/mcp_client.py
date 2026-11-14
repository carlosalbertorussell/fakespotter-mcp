"""
Calls FakeSpotter tools through the public MCP client API.

Every test goes through the mcp 2.x public client (``mcp.client.Client`` in
legacy mode, connected in memory to the real ``server.mcp`` instance), so arguments are JSON-serialised, validated against
the published input schema and returned as protocol content blocks, exactly
as a real MCP client sees them. Nothing here touches server internals.

This is the single place to adapt when the mcp client API changes; the tests
themselves only use ``call_tool`` / ``list_tool_names`` / ``list_tools``.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from mcp.client import Client


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
    async with Client(_server(), mode="legacy") as client:
        result = await client.call_tool(name, arguments)  # -> CallToolResult
    text = "\n".join(block.text for block in result.content if block.type == "text")
    return ToolResult(text=text, is_error=bool(result.is_error))


async def acall_tool(name: str, **params: Any) -> ToolResult:
    """Async variant of :func:`call_tool`."""
    return await _acall(name, {"params": params})


def call_tool(name: str, **params: Any) -> ToolResult:
    """Call tool ``name``; every FakeSpotter tool takes a single ``params`` object."""
    return asyncio.run(acall_tool(name, **params))


async def _alist():
    async with Client(_server(), mode="legacy") as client:
        listed = await client.list_tools()
    assert listed.next_cursor is None, "unexpected tools/list pagination"
    return listed.tools


def list_tools():
    """Tool definitions (``mcp.types.Tool``) as published by tools/list."""
    return asyncio.run(_alist())


def list_tool_names() -> list[str]:
    return sorted(tool.name for tool in list_tools())
