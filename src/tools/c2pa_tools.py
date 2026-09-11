"""
FakeSpotter — tools/c2pa_tools.py
C2PA / Content Credentials Manifest Verifier (tool #25)

Reads and cryptographically verifies C2PA manifests (Content Credentials)
embedded in images, audio, and video files.

C2PA (Coalition for Content Provenance and Authenticity, ISO/IEC 22144)
is the provenance standard adopted by Adobe, Google, Meta, Microsoft,
OpenAI, and 6000+ other organisations. When a file has a C2PA manifest,
FakeSpotter can verify cryptographically:
  - What tool created or edited the file (Adobe Photoshop, DALL-E, Firefly, etc.)
  - Whether AI generation was involved
  - What edits were applied and in what order
  - AI training consent declarations
  - The signer's certificate chain and signing time
  - Whether the manifest was tampered after signing

IMPORTANT LIMIT:
  Absence of a C2PA manifest does not mean the file is authentic.
  Most files in circulation have no C2PA manifest at all.
  A C2PA manifest proves provenance; its absence proves nothing.

Supported formats:
  Images: JPEG, PNG, WebP, AVIF, HEIC, TIFF, GIF
  Video:  MP4, MOV, AVI, MKV
  Audio:  MP3, MP4 audio, WAV
  Documents: PDF (Adobe Acrobat only)

Dependency: c2pa-python>=0.7,<1 (CAI Open Source SDK)
"""
from __future__ import annotations

import io
import json
import tempfile
from pathlib import Path
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

_MAGIC_FORMATS: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff",      "image/jpeg"),
    (b"\x89PNG\r\n",       "image/png"),
    (b"RIFF",              "audio/wav"),    # WAV (RIFF header, checked further below)
    (b"fLaC",              "audio/flac"),
    (b"OggS",              "audio/ogg"),
    (b"%PDF",              "application/pdf"),
    (b"\x00\x00\x00\x18ftypmp4",  "video/mp4"),  # MP4 ftyp box
    (b"\x00\x00\x00\x18ftypM4A",  "audio/mp4"),
    (b"\x00\x00\x00\x1cftyp",     "video/mp4"),
    (b"ID3",               "audio/mpeg"),
    (b"\xff\xfb",          "audio/mpeg"),
]

_EXT_FORMATS: dict[str, str] = {
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".png": "image/png",  ".webp": "image/webp",
    ".avif": "image/avif", ".heic": "image/heic",
    ".tiff": "image/tiff", ".tif": "image/tiff",
    ".gif": "image/gif",
    ".mp4": "video/mp4",  ".mov": "video/quicktime",
    ".avi": "video/x-msvideo", ".mkv": "video/x-matroska",
    ".mp3": "audio/mpeg", ".wav": "audio/wav",
    ".m4a": "audio/mp4",  ".pdf": "application/pdf",
}

def _detect_format(data: bytes, url: str, content_type: str) -> str:
    # 1. Magic bytes
    for magic, fmt in _MAGIC_FORMATS:
        if data[:len(magic)] == magic:
            # Disambiguate RIFF: could be WAV or AVI
            if magic == b"RIFF" and len(data) >= 12:
                riff_type = data[8:12]
                if riff_type == b"AVI ": return "video/x-msvideo"
                return "audio/wav"
            return fmt
    # 2. Content-Type header
    if content_type:
        ct = content_type.split(";")[0].strip()
        if ct.startswith(("image/","audio/","video/","application/pdf")):
            return ct
    # 3. URL extension
    ext = Path(url.split("?")[0]).suffix.lower()
    return _EXT_FORMATS.get(ext, "application/octet-stream")


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------

_AI_GENERATORS = {
    "adobe firefly", "dall-e", "dall·e", "openai", "midjourney",
    "stable diffusion", "stability ai", "kling", "pika", "runwayml",
    "suno", "udio", "musicgen", "riffusion", "elevenlabs",
    "sora", "gen-", "ideogram", "flux", "imagen",
}

def _extract_ai_signals(manifest: dict) -> list[str]:
    """Look for AI generation signals in a manifest."""
    signals: list[str] = []
    cg = manifest.get("claim_generator", "").lower()
    for gen in _AI_GENERATORS:
        if gen in cg:
            signals.append(f"AI generator in claim_generator: {manifest['claim_generator']}")
            break

    for assertion in manifest.get("assertions", []):
        label = assertion.get("label", "")
        data  = assertion.get("data", {})

        if label == "c2pa.training-mining":
            entries = data.get("entries", {})
            for key, val in entries.items():
                use = val.get("use", "")
                signals.append(f"Training consent [{key}]: {use}")

        if "ai_generative" in label.lower() or "generative" in label.lower():
            signals.append(f"AI generative assertion: {label}")

        if label == "c2pa.actions":
            for action in data.get("actions", []):
                act = action.get("action", "")
                if any(k in act for k in ("aiGenerated", "ai_generated", "generated")):
                    params = action.get("parameters", {})
                    desc   = params.get("description", act)
                    signals.append(f"AI generation action: {desc}")

    return signals


def _parse_manifest_store(manifest_json: str) -> dict:
    """Parse the manifest store JSON into a structured forensic result."""
    store = json.loads(manifest_json)
    active_label = store.get("active_manifest", "")
    manifests    = store.get("manifests", {})
    active       = manifests.get(active_label, {})

    sig_info  = active.get("signature_info", {})
    val_status = active.get("validation_status", [])  # non-empty = tampered/invalid

    # Collect all actions
    actions: list[str] = []
    for a in active.get("assertions", []):
        if a.get("label") == "c2pa.actions":
            for act in a.get("data", {}).get("actions", []):
                actions.append(act.get("action", ""))

    ai_signals = _extract_ai_signals(active)

    return {
        "claim_generator": active.get("claim_generator", ""),
        "title":           active.get("title", ""),
        "format":          active.get("format", ""),
        "active_manifest": active_label,
        "manifest_count":  len(manifests),
        "signer_issuer":   sig_info.get("issuer", ""),
        "signing_time":    sig_info.get("time", ""),
        "cert_serial":     sig_info.get("cert_serial_number", ""),
        "validation_errors": val_status,
        "is_tampered":     len(val_status) > 0,
        "actions":         actions,
        "ai_signals":      ai_signals,
        "ingredient_count": len(active.get("ingredients", [])),
        "assertion_count":  len(active.get("assertions", [])),
        "raw_active_manifest": active,
    }


# ---------------------------------------------------------------------------
# Tool: verify_c2pa_manifest
# ---------------------------------------------------------------------------

class VerifyC2PAManifestInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url: str = Field(
        ...,
        description=(
            "Public URL of the media file to inspect. "
            "Supported: JPEG, PNG, WebP, AVIF, HEIC, MP4, MOV, MP3, WAV, PDF. "
            "Most files do NOT have a C2PA manifest — this is normal and expected."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_c2pa_manifest(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_c2pa_manifest",
        annotations={
            "title": "C2PA / Content Credentials Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_c2pa_manifest(params: VerifyC2PAManifestInput) -> str:
        """
        Reads and cryptographically verifies C2PA / Content Credentials manifests
        embedded in media files (ISO/IEC 22144).

        When a file has a C2PA manifest, this tool verifies:
          - Which software created or edited the file (claim_generator)
          - Whether AI generation was declared (c2pa.aiGenerated assertion)
          - Editing history and action sequence
          - AI training consent declarations (c2pa.training-mining)
          - Signer identity (X.509 certificate issuer and signing time)
          - Manifest integrity (tampered manifests fail validation)

        Verdicts:
          C2PA_VALID      — manifest present and cryptographically valid
          C2PA_TAMPERED   — manifest present but integrity check failed
          C2PA_NOT_FOUND  — no C2PA manifest in the file (common; not suspicious)

        IMPORTANT LIMIT:
          Absence of a C2PA manifest does not prove authenticity.
          Most files in circulation have no manifest at all.
          C2PA proves provenance when present; its absence proves nothing.

        Requires: c2pa-python>=0.7,<1 (CAI Open Source SDK, contentauth/c2pa-python)

        Args:
            params.file_url:    URL of the media file
            params.lang:        en | es
            params.report_mode: quick | full
        """
        try:
            # Download
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 c2pa-verifier"},
            ) as client:
                resp = await client.get(params.file_url)
                resp.raise_for_status()
                file_bytes   = resp.content
                content_type = resp.headers.get("content-type", "")

            fmt = _detect_format(file_bytes, params.file_url, content_type)
            flags: list[str] = [f"File format: {fmt}"]

            # Read C2PA manifest
            try:
                import c2pa
            except ImportError:
                return (
                    "[FakeSpotter Error] c2pa-python not installed. "
                    "Add c2pa-python>=0.7,<1 to requirements.txt. "
                    "See: pip install c2pa-python"
                )

            with tempfile.NamedTemporaryFile(
                suffix=Path(params.file_url.split("?")[0]).suffix or ".bin",
                delete=False
            ) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name

            try:
                try:
                    reader = c2pa.Reader(fmt, io.BytesIO(file_bytes))
                    manifest_json = reader.json()
                except Exception:
                    # Fallback: file-based reader
                    reader = c2pa.Reader.from_file(tmp_path)
                    manifest_json = reader.json()

                parsed = _parse_manifest_store(manifest_json)

                if parsed["is_tampered"]:
                    verdict = "C2PA_TAMPERED"
                    trust   = 0
                    for err in parsed["validation_errors"]:
                        flags.append(f"⚠ Validation error: {err.get('code','?')} — {err.get('url','')}")
                else:
                    verdict = "C2PA_VALID"
                    trust   = 100

                flags.append(f"Claim generator: {parsed['claim_generator'] or 'not set'}")
                if parsed["signing_time"]:
                    flags.append(f"Signed: {parsed['signing_time']} by {parsed['signer_issuer'] or 'unknown issuer'}")
                if parsed["ai_signals"]:
                    for sig in parsed["ai_signals"]:
                        flags.append(f"AI signal: {sig}")
                if parsed["actions"]:
                    flags.append(f"Recorded actions: {', '.join(parsed['actions'][:5])}")
                if parsed["manifest_count"] > 1:
                    flags.append(f"Manifest chain: {parsed['manifest_count']} manifests (editing history)")

                findings = {
                    "verdict":       verdict,
                    "trust_score":   trust,
                    "c2pa_present":  True,
                    **parsed,
                    "forensic_flags": flags,
                }

            except Exception as e:
                err_str = str(e).lower()
                if any(k in err_str for k in ("no c2pa", "not found", "missing", "no manifest",
                                               "jumbf", "no active", "no content")):
                    verdict = "C2PA_NOT_FOUND"
                    trust   = 50
                    flags.append(
                        "No C2PA manifest found in this file. "
                        "This is normal for most files — C2PA adoption is not universal. "
                        "Absence of a manifest does not indicate manipulation."
                    )
                    findings = {
                        "verdict":      verdict,
                        "trust_score":  trust,
                        "c2pa_present": False,
                        "forensic_flags": flags,
                    }
                else:
                    return f"[FakeSpotter Error] C2PA read error: {e}"
            finally:
                Path(tmp_path).unlink(missing_ok=True)

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "C2PA_VALID"
                    else i18n.t("verdict_fake", params.lang) if verdict == "C2PA_TAMPERED"
                    else i18n.t("verdict_uncertain", params.lang)
                )
                key = flags[:3]
                return f"{label} ({trust}/100) — {verdict} | {' | '.join(key)}"

            report = ForensicReporter.generate_report("verify_c2pa_manifest", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_verify_c2pa_manifest(mcp)
