# 🕵️‍♂️ FakeSpotter MCP

**AI-Powered Forensic Suite — Automated digital evidence authentication for the era of generative content.**

Built for AI agents, security teams, and auditors via the [Model Context Protocol](https://modelcontextprotocol.io).

FakeSpotter acts as your **Digital Forensic Expert**. Whether validating the authenticity of a financial transaction, verifying identity documents, or performing deepfake analysis on media assets, FakeSpotter delivers cryptographically signed reports to prove what is real and what is synthetic.

*Built by [Carlos A. Russell](https://github.com/carlosalbertorussell) | CISSP · CISM · CISA · CGEIT*

---

## ⚡ Quick Start (Hosted)

Add to your IDE MCP config file:

```json
{
  "mcpServers": {
    "fakespotter": {
      "url": "https://mcpize.com/mcp/fakespotter",
      "auth": "Bearer YOUR_MCPIZE_KEY"
    }
  }
}
```

Restart your IDE. FakeSpotter tools will appear automatically.

> 50 free calls/month. Payments via x402 — USDC on Base.

---

## 🧰 Forensic Toolkit — 18 Specialised Tools

| Tool | Cost/Call | Forensic Domain |
|------|-----------|-----------------|
| `audit_deepfake_video` | $0.50 | Media / Synthetic Content |
| `detect_ai_generated_image` | $0.40 | Media / Synthetic Content |
| `analyze_audio_authenticity` | $0.35 | Media / Synthetic Content |
| `verify_video_metadata` | $0.20 | Media / Synthetic Content |
| `detect_steganography` | $0.25 | Media / Synthetic Content |
| `verify_physical_currency` | $0.25 | Physical / Financial |
| `validate_identity_doc` | $0.40 | Identity / KYC |
| `detect_document_forgery` | $0.35 | Physical / Financial |
| `scan_phishing_url` | $0.15 | Network Security |
| `check_email_headers` | $0.15 | Network Security |
| `analyze_url_reputation` | $0.15 | Network Security |
| `scan_blockchain_provenance` | $0.15 | Crypto / DeFi |
| `verify_nft_authenticity` | $0.20 | Crypto / DeFi |
| `detect_ai_generated_text` | $0.20 | Document / Text |
| `analyze_file_metadata` | $0.15 | Document / Text |
| `verify_document_integrity` | $0.10 | Document / Text |
| `analyze_image_metadata` | $0.20 | OSINT / Identity |
| `verify_social_profile` | $0.20 | OSINT / Identity |

---

## 🛡️ The Forensic Difference: Quick vs. Full Report

Unlike standard scanners, FakeSpotter offers two analysis modes via the `report_mode` parameter:

**`quick`** — Immediate binary verdict for fast agent decisions:
```
✓ AUTHENTIC / VERIFIED (91/100) — No anomalies detected
```

**`full`** — Cryptographically signed Forensic Certificate with evidence breakdown, ready for legal or security review:
```
────────────────────────────────────────────────────────
  FAKESPOTTER FORENSIC CERTIFICATE  v1.0.0
────────────────────────────────────────────────────────
  Tool      : detect_ai_generated_image
  Date/Time : 2025-05-25T14:32:07.412Z
  Report ID : 3f8a2c1d9e4b7f0a2d5e…
────────────────────────────────────────────────────────
  VERDICT   : LIKELY_AUTHENTIC
  CONFIDENCE: 91/100
────────────────────────────────────────────────────────
  FORENSIC FLAGS:
  ✓  None detected
────────────────────────────────────────────────────────
  SHA-256 INTEGRITY:
  3f8a2c1d9e4b7f0a2d5e8c3b1a9f6d4e2c0b8a7f5d3e1c9b7a5f3d1e9c7b5a3
  HMAC-SHA256 SIGNATURE:
  7b2e4a9c1d8f3b6e0a5c2d7f4b1e8a3c6d9f2b5e8a1c4d7f0b3e6a9c2d5f8b1
────────────────────────────────────────────────────────
```

Every full report is HMAC-SHA256 signed and timestamped, ensuring the evidence cannot be altered after analysis.

---

## 🏗️ Architecture

```
Layer 1 — Forensics   Modular detection (ELA, noise analysis, copy-move,
                      LSB steganography, EXIF fingerprinting, text statistics,
                      blockchain API, HTTP heuristics)

Layer 2 — MCP         FastMCP interface exposes 18 forensic modules as
                      @mcp.tool() calls with Pydantic input validation

Layer 3 — Integrity   Every report is HMAC-SHA256 signed and timestamped
```

```
src/
├── server.py              ← MCP router (registers all 18 tools)
├── locales/
│   ├── en.json
│   └── es.json
├── utils/
│   ├── analysis.py        ← ELA, noise, copy-move, LSB, EXIF, text stats
│   ├── media.py           ← httpx (images) + yt-dlp (video/audio)
│   ├── reporter.py        ← HMAC-SHA256 certificate generator
│   └── i18n.py            ← Localisation (EN/ES)
└── tools/
    ├── media_tools.py     ← Tools 1–5
    ├── financial_tools.py ← Tools 6–8
    ├── network_tools.py   ← Tools 9–11
    ├── blockchain_tools.py← Tools 12–13
    ├── document_tools.py  ← Tools 14–16
    └── osint_tools.py     ← Tools 17–18
```

---

## 🔧 Self-Hosting

### Local Mode (stdio — Claude Desktop)

```bash
git clone https://github.com/carlosalbertorussell/fakespotter-mcp
cd fakespotter-mcp
pip install -r requirements.txt
cp .env.example .env   # edit FAKESPOTTER_SECRET
python src/server.py
```

Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "fakespotter": {
      "command": "python",
      "args": ["/absolute/path/to/fakespotter-mcp/src/server.py"]
    }
  }
}
```

### Docker Mode (HTTP — remote/team deployment)

```bash
cp .env.example .env   # set FAKESPOTTER_SECRET and FAKESPOTTER_TRANSPORT=streamable_http
docker build -t fakespotter-mcp .
docker run -p 8000:8000 --env-file .env fakespotter-mcp
```

---

## 🌐 Languages

All tools accept a `lang` parameter: `"en"` (English) or `"es"` (Spanish).

---

## 📋 Requirements

- Python 3.11+
- ffmpeg (for video analysis)
- Dependencies: `fastmcp`, `httpx`, `yt-dlp`, `Pillow`, `opencv-python-headless`, `numpy`, `python-dotenv`

---

## 👤 Author

**Carlos A. Russell** | CISSP · CISM · CISA · CGEIT  
Cybersecurity Specialist & AI Speaker  
[github.com/carlosalbertorussell](https://github.com/carlosalbertorussell)

---

## 🐛 Support

Report issues or request new forensic patterns via [GitHub Issues](https://github.com/carlosalbertorussell/fakespotter-mcp/issues).
