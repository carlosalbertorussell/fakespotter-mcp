"""Chequeo de arranque para CI.
Falla con exit 1 si mcp resolvio a 2.x, si el import se rompe, o si no se
registran las 27 tools esperadas. Es lo minimo que habria frenado el PR #39
antes de llegar al build.
"""
from __future__ import annotations
import asyncio
import importlib.metadata as metadata
import os
import sys
from pathlib import Path
EXPECTED_TOOLS = 27
_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("FAKESPOTTER_TRANSPORT", "stdio")
os.environ.setdefault("FAKESPOTTER_TMP", "/tmp/fakespotter")
Path(os.environ["FAKESPOTTER_TMP"]).mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(_ROOT / "src"))
def fail(message):
  print(f"FAIL: {message}", file=sys.stderr)
  raise SystemExit(1)
def main():
  mcp_version = metadata.version("mcp")
  if int(mcp_version.split(".")[0]) >= 2:
    fail(f"mcp resolvio a {mcp_version}, pero el codigo usa la API v1 (FastMCP). Falta el tope mcp<2.")
  print(f"mcp {mcp_version} - serie v1, OK")
  import server
  instance = next((obj for obj in vars(server).values() if type(obj).__name__ == "FastMCP"), None)
  if instance is None:
    fail("no encontre la instancia FastMCP en src/server.py")
  tools = asyncio.run(instance.list_tools())
  names = sorted(tool.name for tool in tools)
  print(f"tools registradas: {len(names)}")
  for name in names:
    print(f" - {name}")
  if len(names) != EXPECTED_TOOLS:
    fail(f"se esperaban {EXPECTED_TOOLS} tools y se registraron {len(names)}")
  print("OK - install, arranque e inventario verificados")
if __name__ == "__main__":
  main()
  
