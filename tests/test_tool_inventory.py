"""
Gap 5b — the exact tool inventory, listed through the public MCP client API
(the same check scripts/ci_check.py does with mcp.client.Client).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from tests.mcp_client import list_tool_names, list_tools


def _ci_check():
    path = Path(__file__).resolve().parent.parent / "scripts" / "ci_check.py"
    spec = importlib.util.spec_from_file_location("ci_check", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tool_names_match_ci_inventory():
    ci = _ci_check()
    names = list_tool_names()
    assert len(names) == len(set(names))
    assert set(names) == ci.EXPECTED_TOOL_NAMES
    assert len(names) == ci.EXPECTED_TOOLS


def test_every_tool_takes_a_single_params_object():
    # tests/mcp_client.call_tool relies on this calling convention.
    for tool in list_tools():
        assert list(tool.input_schema.get("properties", {})) == ["params"], tool.name
