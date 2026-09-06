# 🕵️‍♂️ FakeSpotter MCP

[![MCPize](https://mcpize.com/badge/@crussell/fakespotter)](https://mcpize.com/mcp/fakespotter)

**Forensic Suite for Digital Evidence Authentication — deterministic checks for financial fraud, document tampering, and phishing.**

Built for AI agents, security teams, and auditors via the [Model Context Protocol](https://modelcontextprotocol.io).

FakeSpotter delivers **binary, reproducible verdicts**: a hash matches or it doesn't, an SPF record validates or it doesn't, a domain resolves or it doesn't. Every result is cryptographically signed with your own key and ready for compliance review.

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

Restart your IDE. All FakeSpotter tools appear automatically.

> 50 free calls/month. Payments via x402 — USDC on Base.

---

## ⚡ FakeSpotter Invoice Guard

Verify supplier invoices before payment — a complete forensic chain in four deterministic steps, each returning a binary verdict and a cryptographically signed certificate.

**Step 1 — Scan the sender's email headers for spoofing:**
```
Use FakeSpotter to check these email headers for spoofing: [paste raw headers]
```
Checks SPF, DKIM, DMARC, From/Return-Path mismatches, and Reply-To hijacking.

**Step 2 — Verify the invoice PDF hasn't been altered:**
```
Use FakeSpotter to verify this invoice file hasn't been modified.
File: https://example.com/invoice.pdf
Known SHA-256 hash: [original hash from sender]
```
Compares the live file hash against the known-good baseline. Any tampering returns `DOCUMENT_TAMPERED`.

**Step 3 — Check the sender's domain reputation:**
```
Use FakeSpotter to analyse the reputation of this domain: supplier-invoices.net
```
Checks DNS resolution, HTTPS validity, redirect chains, and security header posture.

**Step 4 — Fingerprint the attachment:**
```
Use FakeSpotter to analyse this file's metadata: https://example.com/invoice.pdf
```
Produces MD5, SHA-256, SHA-512 hashes, detects file-type mismatches, and flags high-entropy content.

**Step 5 — Get a full signed Forensic Certificate:**

Add `report_mode: "full"` to any tool call to receive a cryptographically signed certificate with HMAC-SHA256 integrity hash — ready for legal or compliance review.

| Tool | Cost/Call | What it checks |
|------|-----------|----------------|
| `check_email_headers` | $0.15 | SPF, DKIM, DMARC, header spoofing |
| `verify_document_integrity` | $0.10 | SHA-256 hash vs known-good baseline |
| `analyze_url_reputation` | $0.15 | DNS, HTTPS, redirect chain, security headers |
| `analyze_file_metadata` | $0.15 | Hash fingerprint, magic bytes, entropy |
| Forensic Certificate | included | HMAC-SHA256 signed, per-user key |
| **Full Invoice Guard run** | **$0.55** | |

---

## 🧰 Production Forensic Toolkit — 13 Tools

| Tool | Cost/Call | Forensic Domain |
|------|-----------|-----------------|
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

## 🔬 Research Tools (not production-validated)

The following tools use **Layer 1 heuristics** — Error Level Analysis (ELA), noise consistency, copy-move detection, LSB steganography analysis, and audio metadata fingerprinting. These techniques were effective against early generative models and remain useful for exploration and research.

They are **not recommended for evidentiary or commercial decisions** without independent validation against your target adversary model. A competent evaluator probing them with recent generative content will find significant false-negative rates. They are included in the server and available to call; they are not part of the production offer.

| Tool | Forensic Domain | Technique |
|------|-----------------|-----------|
| `audit_deepfake_video` | Media / Synthetic Content | Frame-level ELA + metadata |
| `detect_ai_generated_image` | Media / Synthetic Content | ELA + noise + copy-move + EXIF |
| `analyze_audio_authenticity` | Media / Synthetic Content | Metadata + encoding heuristics |
| `verify_video_metadata` | Media / Synthetic Content | Container/platform metadata |
| `detect_steganography` | Media / Synthetic Content | LSB analysis |

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
Layer 1 — Forensics   Hash verification, header parsing, DNS/HTTP
                      reputation checks, entropy and magic-byte
                      analysis, text statistics, blockchain API

Layer 2 — MCP         FastMCP exposes forensic modules as
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
