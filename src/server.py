"""
FakeSpotter MCP Server
AI-Powered Forensic Suite — 18 Specialised Detection Tools
Built by Carlos A. Russell | CISSP · CISM · CISA · CGEIT
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

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
    instructions=(
        "FakeSpotter is an AI-powered forensic suite for digital evidence authentication. "
        "It detects deepfakes, AI-generated content, counterfeit documents, phishing, "
        "on-chain fraud, and steganography. "
        "Every tool accepts a 'report_mode' parameter: "
        "'quick' returns an immediate binary verdict; "
        "'full' returns a cryptographically signed Forensic Certificate with evidence breakdown. "
        "Supported languages: 'en' (English) and 'es' (Spanish)."
    ),
)


# ---------------------------------------------------------------------------
# Register all 18 tools
# ---------------------------------------------------------------------------

_media.register_all(mcp)        # Tools  1–5  : Media / Synthetic Content
_financial.register_all(mcp)    # Tools  6–8  : Physical / Financial
_network.register_all(mcp)      # Tools  9–11 : Network / Cyber
_blockchain.register_all(mcp)   # Tools 12–13 : Blockchain / DeFi
_document.register_all(mcp)     # Tools 14–16 : Documents / Text
_osint.register_all(mcp)        # Tools 17–18 : OSINT / Identity

logger.info("FakeSpotter MCP server initialised — 18 forensic tools registered.")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    transport = os.environ.get("FAKESPOTTER_TRANSPORT", "stdio")

    if transport == "streamable_http":
        port = int(os.environ.get("FAKESPOTTER_PORT", "8000"))
        logger.info("Starting FakeSpotter in HTTP mode on port %d", port)
        mcp.run(transport="streamable_http", port=port)
    else:
        logger.info("Starting FakeSpotter in stdio mode")
        mcp.run()
