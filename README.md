# 🕵️‍♂️ FakeSpotter MCP

[![MCPize](https://mcpize.com/badge/@crussell/fakespotter)](https://mcpize.com/mcp/fakespotter)

**AI-Powered Forensic Suite — Automated digital evidence authentication for the era of generative content.**

Built for AI agents, security teams, and auditors via the [Model Context Protocol](https://modelcontextprotocol.io).

FakeSpotter acts as your **Digital Forensic Expert**. Whether validating the authenticity of a financial transaction, verifying identity documents, or performing deepfake analysis on media assets, FakeSpotter delivers cryptographically signed reports to prove what is real and what is synthetic.

*Built by [Carlos A. Russell](https://github.com/carlosalbertorussell) | CISSP · CISM · CISA · CGEIT*

---

## ⚡ Quick Start (Hosted)

Add to your IDE MCP config:

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

Restart your IDE. All 18 FakeSpotter tools appear automatically.

> 50 free calls/month. Payments via x402 — USDC on Base.

---

## 🔍 Quick Start: Real-World Example

**Scenario:** A finance team receives an invoice via email and needs to verify it before payment.

**Step 1 — Scan the sender's email headers for spoofing:**
```
Use FakeSpotter to check these email headers for spoofing: [paste raw headers]
```
FakeSpotter checks SPF, DKIM, DMARC, From/Return-Path mismatches, and Reply-To hijacking.

**Step 2 — Verify the invoice PDF hasn't been altered:**
```
Use FakeSpotter to verify this invoice file hasn't been modified.
File: https://example.com/invoice.pdf
Known SHA-256 hash: [original hash from sender]
```
FakeSpotter compares the live file hash against the known-good baseline. Any tampering returns `DOCUMENT_TAMPERED`.

**Step 3 — Check the sender's domain reputation:**
```
Use FakeSpotter to analyse the reputation of this domain: supplier-invoices.net
```
FakeSpotter checks DNS resolution, HTTPS validity, redirect chains, and security header posture.

**Step 4 — Get a full signed Forensic Certificate:**

Add `report_mode: "full"` to any tool call to receive a cryptographically signed certificate with HMAC-SHA256 integrity hash — ready for legal or compliance review.

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
| `scan_phishing_url` | $0.30 | Network Security |
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

## 🛡️ Quick vs. Full Report

Every tool accepts a `report_mode` parameter:

**`quick`** — Immediate binary verdict:
```
✓ AUTHENTIC / VERIFIED (91/100) — No anomalies detected
```

**`full`** — Cryptographically signed Forensic Certificate:
```
────────────────────────────────────────────────────────
  FAKESPOTTER FORENSIC CERTIFICATE  v1.0.0
────────────────────────────────────────────────────────
  Tool      : verify_document_integrity
  Date/Time : 2025-05-25T14:32:07.412Z
  Report ID : 3f8a2c1d9e4b7f0a2d5e…
  Signing   : PER_USER
────────────────────────────────────────────────────────
  VERDICT   : DOCUMENT_INTACT
  CONFIDENCE: 100/100
────────────────────────────────────────────────────────
  FORENSIC FLAGS:
  ✓  None detected
────────────────────────────────────────────────────────
  SHA-256 INTEGRITY:
  3f8a2c1d9e4b7f0a2d5e8c3b1a9f6d4e…
  HMAC-SHA256 SIGNATURE:
  7b2e4a9c1d8f3b6e0a5c2d7f4b1e8a3c…
────────────────────────────────────────────────────────
```

Every full report is **HMAC-SHA256 signed with your personal key** — chain of custody stays with you, not the platform.

---

## 🔐 Per-User Cryptographic Signing

FakeSpotter uses **per-user signing keys**. When you subscribe via MCPize, you provide your own `FAKESPOTTER_SECRET`. Your certificates are signed with your key — no shared platform key, no shared trust.

Generate your key:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 🏗️ Architecture

```
Layer 1 — Forensics   ELA, noise analysis, copy-move detection,
                      LSB steganography, EXIF fingerprinting,
                      text statistics, blockchain API, HTTP heuristics

Layer 2 — MCP         FastMCP exposes 18 forensic modules as
                      @mcp.tool() calls with Pydantic validation

Layer 3 — Integrity   Every report is HMAC-SHA256 signed with
                      the user's own key and timestamped
```

---

## 🔧 Self-Hosting

### Local Mode (stdio — Claude Desktop)

```bash
git clone https://github.com/carlosalbertorussell/fakespotter-mcp
cd fakespotter-mcp
pip install -r requirements.txt
cp .env.example .env   # set FAKESPOTTER_SECRET
python src/server.py
```

Claude Desktop config:
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

### Docker Mode (HTTP)

```bash
cp .env.example .env
docker build -t fakespotter-mcp .
docker run -p 8000:8000 --env-file .env fakespotter-mcp
```

---

## 🌐 Languages

All tools accept `lang`: `"en"` (English) or `"es"` (Spanish).

---

## 👤 Author

**Carlos A. Russell** | CISSP · CISM · CISA · CGEIT  
Cybersecurity Specialist & AI Speaker  
[github.com/carlosalbertorussell](https://github.com/carlosalbertorussell)  
[myothercarisarobot.com](https://myothercarisarobot.com)

---

## 🐛 Support

Report issues or request new forensic patterns via [GitHub Issues](https://github.com/carlosalbertorussell/fakespotter-mcp/issues).
