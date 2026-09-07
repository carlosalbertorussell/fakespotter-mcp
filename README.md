# 🕵️‍♂️ FakeSpotter MCP

[![MCPize](https://mcpize.com/badge/@crussell/fakespotter)](https://mcpize.com/mcp/fakespotter)

**Forensic authentication of digital evidence — 19 tools covering document integrity, email spoofing, AI-generated content, and media deepfakes.**

Built for AI agents, security teams, and auditors via the [Model Context Protocol](https://modelcontextprotocol.io).

Every verdict is cryptographically signed with your own key (HMAC-SHA256, per-user). Chain of custody stays with you, not the platform.

*Built by [Carlos A. Russell](https://github.com/carlosalbertorussell) | CISSP · CISM · CISA · CGEIT*

---

## ⚡ Quick Start (Hosted)

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

> 50 free calls/month. Payments via x402 — USDC on Base.

---

## ⚡ FakeSpotter Invoice Guard

Verify supplier invoices before payment — four deterministic steps, each returning a binary verdict and a signed certificate.

**Step 1 — Email header authentication:**
```
Use FakeSpotter to check these email headers for spoofing: [paste raw headers]
```
Checks SPF, DKIM, DMARC, From/Return-Path mismatches, and Reply-To hijacking.

**Step 2 — Document integrity:**
```
Use FakeSpotter to verify this invoice file hasn't been modified.
File: https://example.com/invoice.pdf
Known SHA-256 hash: [original hash from sender]
```
Compares the live file hash against the known-good baseline. Any tampering returns `DOCUMENT_TAMPERED`.

**Step 3 — Domain reputation:**
```
Use FakeSpotter to analyse the reputation of this domain: supplier-invoices.net
```
Checks DNS resolution, HTTPS validity, redirect chains, and security header posture.

**Step 4 — File fingerprint:**
```
Use FakeSpotter to analyse this file's metadata: https://example.com/invoice.pdf
```
MD5, SHA-256, SHA-512 hashes, magic-byte file type verification, entropy analysis.

**Step 5 — Full signed certificate:** add `report_mode: "full"` to any call.

| Tool | Cost/Call | What it checks |
|------|-----------|----------------|
| `check_email_headers` | $0.15 | SPF, DKIM, DMARC, header spoofing |
| `verify_document_integrity` | $0.10 | SHA-256 hash vs known-good baseline |
| `analyze_url_reputation` | $0.15 | DNS, HTTPS, redirect chain, security headers |
| `analyze_file_metadata` | $0.15 | Hash fingerprint, magic bytes, entropy |
| Forensic Certificate | included | HMAC-SHA256 signed, per-user key |
| **Full Invoice Guard run** | **$0.55** | |

---

## 🧠 AI-Generated Content Detection

Five tools backed by neural ensemble classifiers (HuggingFace + Sightengine). All backends are **BYOK** — you supply your own free API keys; FakeSpotter never holds them. Without keys, tools fall back to Layer-1 heuristics with an explicit `LAYER_1_FALLBACK` flag in the certificate.

**Supported audio formats:** WAV, MP3, FLAC, OGG/Opus (WhatsApp, Telegram), M4A/AAC (iOS), WebM, AMR, 3GP — all converted to WAV 16 kHz mono before analysis.

| Tool | Cost/Call | Backends | Best for |
|------|-----------|----------|----------|
| `detect_ai_generated_image` | $0.40 | HF × 2 + Sightengine | Images from Midjourney, DALL-E, Flux, SD |
| `audit_deepfake_video` | $0.50 | HF × 2 + Sightengine (frame sampling) | Face-swap, synthetic video |
| `analyze_audio_authenticity` | $0.35 | HF × 2 (Wav2Vec2) | Cloned/synthetic voice |
| `detect_ai_generated_music` | $0.30 | HF music model + Sightengine ai-music | Suno, Udio, MusicGen, Riffusion |
| `detect_ai_generated_text` | $0.20 | HF RoBERTa × 2 + optional SynthID | GPT/Claude/Gemini text |

**Required keys (all free-tier available):**
- `hf_token` — [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) (free account)
- `se_user` / `se_secret` — [sightengine.com](https://sightengine.com/pricing) (free tier: 1000 ops/month)

**Attribution:** when Sightengine detects AI music, it returns the likely generator (Suno, Udio, Riffusion, MusicGen, etc.).

---

## 🧰 Deterministic Forensic Toolkit — 12 Tools

Results are binary and reproducible. A hash matches or it doesn't; an SPF record validates or it doesn't.

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
| `analyze_file_metadata` | $0.15 | Document / Text |
| `verify_document_integrity` | $0.10 | Document / Text |
| `analyze_image_metadata` | $0.20 | OSINT / Identity |
| `verify_social_profile` | $0.20 | OSINT / Identity |

---

## 🔬 Layer-1 Heuristic Tools

These two tools use structural heuristics only — no neural backend available. Results are useful for exploration and preliminary screening; treat them as signals, not verdicts.

| Tool | Technique | Limitation |
|------|-----------|------------|
| `verify_video_metadata` | Container/platform metadata consistency | Checks upload date, like ratios, codec signatures — not pixel-level analysis |
| `detect_steganography` | LSB channel analysis | Detects LSB embedding in natural images; ineffective against adaptive or JPEG-domain steganography |

---

## ⚠️ Declared Limits

A forensic provider that overreaches is a liability, not a tool. The table below is what we know about where each category fails.

### Deterministic tools (Invoice Guard)

| Tool | Known limit |
|------|-------------|
| `verify_document_integrity` | 0% FP, 0% FN by SHA-256 construction — unless the attacker also controls the reference hash |
| `analyze_file_metadata` | File-type mismatch: deterministic. Entropy signal alone (+15 pts) falls below REVIEW\_RECOMMENDED threshold — a high-entropy file with no extension mismatch is not flagged. Fix pending. |
| `check_email_headers` | Parses MTA pre-evaluated results. Does not perform live DNS lookups. Senders without DMARC score MODERATE\_RISK as a false positive. |
| `analyze_url_reputation` | FP rate ~67% on established domains missing 2+ security headers (x-frame-options, x-content-type-options). Threshold tuning pending. |

### AI detection tools (neural ensemble)

| Tool | Known limit |
|------|-------------|
| `detect_ai_generated_image` | HF models trained pre-2024. Accuracy degrades on outputs from Flux 1.1, Midjourney v7, DALL-E 4, and any generator released after training cutoff. Monthly health check alerts on drift. |
| `audit_deepfake_video` | Frame-level image classification applied to video. Temporal artifacts (motion inconsistency, audio-video sync) are not analysed. |
| `analyze_audio_authenticity` | Wav2Vec2 models trained on ASVspoof 2021. Performance on post-2024 TTS systems (ElevenLabs v3, Suno vocal, Sora audio) is not benchmarked. |
| `detect_ai_generated_music` | Accuracy is lower on vocal-heavy tracks; best on instrumentals. Heavily re-encoded files (low-bitrate MP3) may lose the spectral artifacts the models look for. |
| `detect_ai_generated_text` | RoBERTa models trained pre-2024. Degrades on newer LLMs, edited AI text, and mixed human/AI content. Not reliable for Spanish. Not suitable as sole evidence for misconduct allegations. |
| All neural tools | A high score is strong evidence. A low score is **not** proof of human origin. |

### SynthID watermark detection

SynthID detects **Kirchenbauer-scheme watermarks only**. ChatGPT, Claude, and Gemini in production **do not watermark their output**. A negative SynthID result never means the text is human-written. See [docs/synthid-setup.md](docs/synthid-setup.md).

### What FakeSpotter does NOT do

- Does not replace a DMARC enforcement policy
- Does not validate the legal identity of a corporate entity
- Does not detect adversarial manipulation of email headers by an attacker with control of the sending domain's DNS
- Does not provide real-time threat intelligence feeds
- Does not guarantee detection of generators released after the last corpus refresh
- Does not produce legally binding authentication — results are forensic signals for human review

---

## 🛡️ Quick vs. Full Report

Every tool accepts `report_mode`:

**`quick`** — immediate binary verdict:
```
✓ AUTHENTIC / VERIFIED (91/100) — No anomalies detected
```

**`full`** — cryptographically signed Forensic Certificate:
```
────────────────────────────────────────────────────────
  FAKESPOTTER FORENSIC CERTIFICATE  v1.0.0
────────────────────────────────────────────────────────
  Tool      : verify_document_integrity
  Date/Time : 2026-09-06T14:32:07.412Z
  Report ID : 3f8a2c1d9e4b7f0a2d5e…
  Signing   : PER_USER
────────────────────────────────────────────────────────
  VERDICT   : DOCUMENT_INTACT
  CONFIDENCE: 100/100
────────────────────────────────────────────────────────
  FORENSIC FLAGS:
  ✓  None detected
────────────────────────────────────────────────────────
  SHA-256 INTEGRITY:   3f8a2c1d9e4b7f0a2d5e8c3b1a9f6d4e…
  HMAC-SHA256 SIGNATURE: 7b2e4a9c1d8f3b6e0a5c2d7f4b1e8a3c…
────────────────────────────────────────────────────────
```

---

## 🔐 Per-User Cryptographic Signing

When you subscribe via MCPize, you provide your own `FAKESPOTTER_SECRET`. Certificates are signed with your key — no shared platform key, no shared trust.

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 🏗️ Architecture

```
Layer 0 — Neural      HuggingFace Inference API + Sightengine (BYOK).
           Classifiers Ensemble scored by confidence weight. Falls back
                       to Layer 1 if no keys provided.

Layer 1 — Forensics   Hash verification, header parsing, DNS/HTTP checks,
                       entropy, magic bytes, LSB analysis, text statistics,
                       blockchain API, HTTP heuristics.

Layer 2 — MCP         FastMCP exposes 19 forensic modules as @mcp.tool()
                       calls with Pydantic validation.

Layer 3 — Integrity   Every report is HMAC-SHA256 signed with the user's
                       own key and timestamped. Chain of custody: client-side.
```

---

## 🔧 Self-Hosting

### Local (stdio — Claude Desktop)

```bash
git clone https://github.com/carlosalbertorussell/fakespotter-mcp
cd fakespotter-mcp
pip install -r requirements.txt
cp .env.example .env   # set FAKESPOTTER_SECRET
python src/server.py
```

### Docker (HTTP)

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
