"""
FakeSpotter MCP Server
AI-Powered Forensic Suite — 21 Forensic Tools
Built by Carlos A. Russell | CISSP · CISM · CISA · CGEIT
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
import os
_PORT = int(os.environ.get("PORT", 8081))

# Ensure src/ is on the path for relative imports
sys.path.insert(0, str(Path(__file__).parent))

from dotenv import load_dotenv
load_dotenv()

from mcp.server.fastmcp import FastMCP

import tools.media_tools       as _media
import tools.financial_tools   as _financial
import tools.network_tools     as _network
import tools.blockchain_tools  as _blockchain
import tools.document_tools    as _document
import tools.osint_tools       as _osint
import tools.qr_tools          as _qr
import tools.signature_tools   as _sig

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("fakespotter")


# ---------------------------------------------------------------------------
# Server initialisation
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "fakespotter_mcp",
    host="0.0.0.0",
    port=_PORT,
    instructions=(
        "FakeSpotter is a forensic suite for digital evidence authentication. "
        "The recommended workflow is FakeSpotter Invoice Guard: a four-step "
        "deterministic chain to verify supplier invoices before payment. "
        "Step 1 — check_email_headers: authenticates SPF, DKIM, DMARC, "
        "From/Return-Path mismatches, and Reply-To hijacking. "
        "Step 2 — verify_document_integrity: compares the document's SHA-256 "
        "hash against a known-good baseline; returns DOCUMENT_INTACT or "
        "DOCUMENT_TAMPERED. "
        "Step 3 — analyze_url_reputation: checks DNS resolution, HTTPS validity, "
        "redirect chains, and security header posture of the sender's domain. "
        "Step 4 — analyze_file_metadata: produces MD5/SHA-256/SHA-512 hashes, "
        "detects file-type mismatches via magic bytes, and flags high entropy. "
        "All four tools accept report_mode='full' to return a cryptographically "
        "signed Forensic Certificate (HMAC-SHA256, per-user key). "
        "Additional production tools cover phishing URLs, blockchain provenance, "
        "identity documents, physical currency, OSINT, and AI-generated text. "
        "All tools accept a 'lang' parameter: 'en' (English) or 'es' (Spanish)."
    ),
)

# ---------------------------------------------------------------------------
# Register all 21 tools
# ---------------------------------------------------------------------------

_media.register_all(mcp)        # Tools  1–5  : Media / Synthetic Content
_financial.register_all(mcp)    # Tools  6–8  : Physical / Financial
_network.register_all(mcp)      # Tools  9–11 : Network / Cyber
_blockchain.register_all(mcp)   # Tools 12–13 : Blockchain / DeFi
_document.register_all(mcp)     # Tools 14–16 : Documents / Text
_osint.register_all(mcp)        # Tools 17–18 : OSINT / Identity
_qr.register_all(mcp)           # Tool  19–20 : QR / Document
_sig.register_all(mcp)          # Tool  21    : Digital Signatures

logger.info("FakeSpotter MCP server initialised — 21 forensic tools registered.")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting FakeSpotter on 0.0.0.0:%d", _PORT)
    mcp.run(transport="streamable-http")
