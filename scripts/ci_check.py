"""Chequeo de arranque para CI.
Falla con exit 1 si mcp resolvio a 2.x, si el import se rompe, o si el
conjunto de tools registradas no es exactamente EXPECTED_TOOL_NAMES (una tool
renombrada, perdida o agregada sin actualizar esta lista rompe el build).
Es lo minimo que habria frenado el PR #39 antes de llegar al build.
"""
from __future__ import annotations
import asyncio
import importlib.metadata as metadata
import os
import sys
from pathlib import Path
EXPECTED_TOOLS = 29  # leido por scripts/check_docs_sync.py contra el README
EXPECTED_TOOL_NAMES = frozenset({
  # Media / contenido sintetico
  "audit_deepfake_video", "detect_ai_generated_image", "analyze_audio_authenticity",
  "verify_video_metadata", "detect_steganography", "detect_ai_generated_music",
  # Fisico / financiero
  "verify_physical_currency", "validate_identity_doc", "detect_document_forgery",
  # Red / ciber
  "scan_phishing_url", "check_email_headers", "analyze_url_reputation",
  # Blockchain
  "scan_blockchain_provenance", "verify_nft_authenticity",
  # Documentos / texto
  "detect_ai_generated_text", "analyze_file_metadata", "verify_document_integrity",
  # OSINT
  "analyze_image_metadata", "verify_social_profile",
  # Invoice Guard extendido / identidad
  "inspect_qr_code", "verify_digital_signature", "verify_rfc3161_timestamp",
  "analyze_email_thread", "validate_bank_account", "validate_mrz", "analyze_pdf_metadata",
  "verify_c2pa_manifest", "validate_identity_liveness", "correlate_documents",
})
assert len(EXPECTED_TOOL_NAMES) == EXPECTED_TOOLS, "EXPECTED_TOOLS y EXPECTED_TOOL_NAMES no coinciden"
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
  if len(names) != len(set(names)):
    fail(f"hay nombres de tool duplicados: {sorted(n for n in set(names) if names.count(n) > 1)}")
  missing = sorted(EXPECTED_TOOL_NAMES - set(names))
  unexpected = sorted(set(names) - EXPECTED_TOOL_NAMES)
  if missing or unexpected:
    fail(f"inventario de tools distinto al esperado: faltan {missing}, sobran {unexpected}")
  print("OK - install, arranque e inventario verificados")
if __name__ == "__main__":
  main()
  
