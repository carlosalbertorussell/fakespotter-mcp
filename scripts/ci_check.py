"""Chequeo de arranque para CI.
Falla con exit 1 si mcp no resolvio a la serie 2.x, si el import se rompe, o si
el inventario de tools (listado por el protocolo MCP, via la API publica del
cliente) no coincide exactamente con los 29 nombres esperados. Es lo minimo que
habria frenado el PR #39 antes de llegar al build.
"""
from __future__ import annotations
import asyncio
import importlib.metadata as metadata
import os
import sys
from pathlib import Path
EXPECTED_TOOLS = 29  # leido por scripts/check_docs_sync.py contra el README
EXPECTED_TOOL_NAMES = frozenset({
  "analyze_audio_authenticity",
  "analyze_email_thread",
  "analyze_file_metadata",
  "analyze_image_metadata",
  "analyze_pdf_metadata",
  "analyze_url_reputation",
  "audit_deepfake_video",
  "check_email_headers",
  "correlate_documents",
  "detect_ai_generated_image",
  "detect_ai_generated_music",
  "detect_ai_generated_text",
  "detect_document_forgery",
  "detect_steganography",
  "inspect_qr_code",
  "scan_blockchain_provenance",
  "scan_phishing_url",
  "validate_bank_account",
  "validate_identity_doc",
  "validate_identity_liveness",
  "validate_mrz",
  "verify_c2pa_manifest",
  "verify_digital_signature",
  "verify_document_integrity",
  "verify_nft_authenticity",
  "verify_physical_currency",
  "verify_rfc3161_timestamp",
  "verify_social_profile",
  "verify_video_metadata",
})
_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("FAKESPOTTER_TMP", "/tmp/fakespotter")
Path(os.environ["FAKESPOTTER_TMP"]).mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(_ROOT / "src"))
def fail(message):
  print(f"FAIL: {message}", file=sys.stderr)
  raise SystemExit(1)
async def list_tool_names(instance):
  # Cliente MCP real (handshake initialize + tools/list sobre JSON-RPC en memoria),
  # no los internos del servidor.
  from mcp.client import Client
  async with Client(instance, mode="legacy") as client:
    result = await client.list_tools()
    if result.next_cursor is not None:
      fail("tools/list devolvio paginacion inesperada")
    return [tool.name for tool in result.tools]
def main():
  if len(EXPECTED_TOOL_NAMES) != EXPECTED_TOOLS:
    fail(f"EXPECTED_TOOL_NAMES tiene {len(EXPECTED_TOOL_NAMES)} nombres, EXPECTED_TOOLS={EXPECTED_TOOLS}")
  mcp_version = metadata.version("mcp")
  if int(mcp_version.split(".")[0]) != 2:
    fail(f"mcp resolvio a {mcp_version}, pero el codigo usa la API v2 (MCPServer). Revisar el pin mcp>=2.3.0,<3.")
  print(f"mcp {mcp_version} - serie v2, OK")
  from mcp.server.mcpserver import MCPServer
  import server
  instance = getattr(server, "mcp", None)
  if not isinstance(instance, MCPServer):
    fail("no encontre la instancia MCPServer `mcp` en src/server.py")
  names = asyncio.run(list_tool_names(instance))
  print(f"tools registradas: {len(names)}")
  for name in sorted(names):
    print(f" - {name}")
  if len(names) != len(set(names)):
    fail(f"tools/list devolvio nombres duplicados: {sorted(n for n in set(names) if names.count(n) > 1)}")
  missing = sorted(EXPECTED_TOOL_NAMES - set(names))
  unexpected = sorted(set(names) - EXPECTED_TOOL_NAMES)
  if missing or unexpected:
    fail(f"inventario distinto al esperado: faltan {missing}, sobran {unexpected}")
  if len(names) != EXPECTED_TOOLS:
    fail(f"se esperaban {EXPECTED_TOOLS} tools y se registraron {len(names)}")
  print("OK - install, arranque e inventario verificados")
if __name__ == "__main__":
  main()
