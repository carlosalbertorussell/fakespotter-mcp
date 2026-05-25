"""
FakeSpotter — Document & Text Forensic Tools (3 tools)
───────────────────────────────────────────────────────
14. detect_ai_generated_text — Statistical heuristics for AI-written text
15. analyze_file_metadata    — Hash fingerprint + metadata extraction
16. verify_document_integrity — Hash comparison against known-good baseline
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.analysis import analyze_text_authenticity, calculate_hashes
from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "AI" in verdict or "TAMPERED" in verdict
        else i18n.t("verdict_authentic", lang) if "HUMAN" in verdict or "INTACT" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


# ---------------------------------------------------------------------------
# Tool 14: detect_ai_generated_text
# ---------------------------------------------------------------------------

class DetectAITextInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    text: str = Field(
        ...,
        description="Text to analyse for AI generation markers (minimum 30 words)",
        min_length=50,
        max_length=50_000,
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_ai_generated_text(mcp: FastMCP) -> None:

    @mcp.tool(
        name="detect_ai_generated_text",
        annotations={
            "title": "AI-Generated Text Detector",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        },
    )
    async def detect_ai_generated_text(params: DetectAITextInput) -> str:
        """
        Heuristic analysis to detect AI-generated text (GPT, Claude, Gemini, etc.).

        Statistical signals used:
        - Burstiness (σ/μ of sentence lengths): human writing is more variable
        - Type-Token Ratio (vocabulary richness): AI tends to repeat phrases
        - Filler phrase density: AI models overuse specific connective phrases
        - Paragraph uniformity: AI produces suspiciously consistent paragraph lengths
        - Punctuation variance

        Limitation: statistical detection; not a neural classifier.
        Mixed human/AI text or edited AI text may score lower.

        Args:
            params.text: Text to analyse (50 chars minimum)
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: AI probability verdict or signed Forensic Certificate
        """
        try:
            result = analyze_text_authenticity(params.text)

            if "error" in result:
                return f"[FakeSpotter] {result['error']}"

            verdict  = result["verdict"]
            ai_score = result["ai_probability_score"]
            flags: list[str] = []

            if result["flags"]["low_burstiness"]:
                flags.append(f"Low sentence-length variance (burstiness={result['burstiness']})")
            if result["flags"]["low_vocabulary"]:
                flags.append(f"Low vocabulary richness (TTR={result['vocabulary_richness_ttr']})")
            if result["flags"]["high_filler"]:
                flags.append(f"High AI filler phrase density ({result['filler_phrase_count']} phrases)")
            if result["flags"]["uniform_paragraphs"]:
                flags.append("Suspiciously uniform paragraph lengths")

            findings = {
                "verdict": verdict,
                "ai_probability_score": ai_score,
                "trust_score": 100 - ai_score,
                "word_count": result["word_count"],
                "sentence_count": result["sentence_count"],
                "burstiness": result["burstiness"],
                "vocabulary_richness_ttr": result["vocabulary_richness_ttr"],
                "filler_phrase_count": result["filler_phrase_count"],
                "filler_density": result["filler_density"],
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - ai_score, flags, params.lang)

            report = ForensicReporter.generate_report("detect_ai_generated_text", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 15: analyze_file_metadata
# ---------------------------------------------------------------------------

class AnalyzeFileMetadataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url: str = Field(
        ...,
        description="Public URL of any file to fingerprint (image, PDF, document, binary)",
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_file_metadata(mcp: FastMCP) -> None:

    @mcp.tool(
        name="analyze_file_metadata",
        annotations={
            "title": "File Metadata Analyser",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_file_metadata(params: AnalyzeFileMetadataInput) -> str:
        """
        Downloads a file and produces a complete forensic fingerprint.

        Provides:
        - MD5, SHA-256, SHA-512 cryptographic hashes
        - File size and content-type
        - Server-side metadata (Last-Modified, ETag, CDN headers)
        - Magic byte detection (actual file type vs declared extension)
        - Entropy measurement (high entropy → encrypted/compressed/packed)

        Args:
            params.file_url: URL of the file to fingerprint
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: File forensic report or signed Forensic Certificate
        """
        try:
            flags: list[str] = []
            score  = 0

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 forensic-scanner"},
            ) as client:
                async with client.stream("GET", params.file_url) as resp:
                    resp.raise_for_status()

                    content_type    = resp.headers.get("content-type", "unknown")
                    last_modified   = resp.headers.get("last-modified", "")
                    etag            = resp.headers.get("etag", "")
                    server          = resp.headers.get("server", "")
                    content_length  = resp.headers.get("content-length")

                    MAX_BYTES = 30 * 1024 * 1024  # 30 MB
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes(65536):
                        total += len(chunk)
                        if total > MAX_BYTES:
                            return "[FakeSpotter Error] File too large for metadata analysis (max 30 MB)"
                        chunks.append(chunk)

            content = b"".join(chunks)
            hashes  = calculate_hashes(content)
            size_bytes = len(content)

            # Magic bytes detection (common formats)
            MAGIC_BYTES: dict[bytes, str] = {
                b"\xff\xd8\xff":   "JPEG image",
                b"\x89PNG\r\n":    "PNG image",
                b"GIF8":           "GIF image",
                b"%PDF":           "PDF document",
                b"PK\x03\x04":    "ZIP archive (or DOCX/XLSX/PPTX)",
                b"\x7fELF":        "ELF executable (Linux binary)",
                b"MZ":             "PE executable (Windows binary)",
                b"\xca\xfe\xba\xbe": "Mach-O executable (macOS binary)",
            }
            detected_type = "Unknown"
            for magic, label in MAGIC_BYTES.items():
                if content[:len(magic)] == magic:
                    detected_type = label
                    break

            # Check declared vs actual type
            declared_ext = params.file_url.rsplit(".", 1)[-1].lower() if "." in params.file_url else ""
            mismatch_map = {
                "jpg":  "JPEG", "jpeg": "JPEG", "png": "PNG",
                "gif":  "GIF",  "pdf":  "PDF",  "zip": "ZIP",
                "exe":  "PE",   "elf":  "ELF",
            }
            expected = mismatch_map.get(declared_ext, "")
            if expected and expected.lower() not in detected_type.lower():
                score += 40
                flags.append(f"File type mismatch: extension .{declared_ext} but magic bytes indicate {detected_type}")

            # Entropy (byte randomness)
            import math as _math
            byte_counts = [0] * 256
            for b in content:
                byte_counts[b] += 1
            entropy = -sum(
                (c / size_bytes) * _math.log2(c / size_bytes)
                for c in byte_counts if c > 0
            )
            if entropy > 7.8:
                score += 15
                flags.append(f"Very high entropy ({entropy:.2f}/8.0) — file may be encrypted or packed")

            score = min(100, score)
            verdict = (
                "SUSPICIOUS_FILE" if score >= 50
                else "REVIEW_RECOMMENDED" if score >= 25
                else "FILE_CLEAN"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "file_url": params.file_url,
                "file_size_bytes": size_bytes,
                "file_size_human": f"{size_bytes / 1024:.1f} KB" if size_bytes < 1024*1024 else f"{size_bytes/1024/1024:.2f} MB",
                "detected_file_type": detected_type,
                "declared_content_type": content_type,
                "entropy": round(entropy, 3),
                "hashes": hashes,
                "server_metadata": {
                    "server": server,
                    "last_modified": last_modified,
                    "etag": etag,
                    "content_length_header": content_length,
                },
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("analyze_file_metadata", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 16: verify_document_integrity
# ---------------------------------------------------------------------------

class VerifyDocumentIntegrityInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url: str = Field(..., description="Public URL of the document to verify")
    expected_sha256: str = Field(
        ...,
        description="Known-good SHA-256 hash to compare against",
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-fA-F]{64}$",
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_document_integrity(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_document_integrity",
        annotations={
            "title": "Document Integrity Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_document_integrity(params: VerifyDocumentIntegrityInput) -> str:
        """
        Verifies a document's integrity by comparing its SHA-256 hash against a
        known-good baseline.

        Use case: Confirm that a contract, certificate, or evidence file has not
        been altered since its original hash was recorded.

        Args:
            params.file_url: URL of file to verify
            params.expected_sha256: Known-good SHA-256 hash (64 hex chars)
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: INTACT or TAMPERED verdict with hash comparison
        """
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 forensic-scanner"},
            ) as client:
                async with client.stream("GET", params.file_url) as resp:
                    resp.raise_for_status()
                    chunks: list[bytes] = []
                    total = 0
                    async for chunk in resp.aiter_bytes(65536):
                        total += len(chunk)
                        if total > 50 * 1024 * 1024:
                            return "[FakeSpotter Error] File too large for integrity check (max 50 MB)"
                        chunks.append(chunk)

            content = b"".join(chunks)
            actual_hash = hashlib.sha256(content).hexdigest()
            expected_hash = params.expected_sha256.lower()

            match = actual_hash == expected_hash
            verdict = "DOCUMENT_INTACT" if match else "DOCUMENT_TAMPERED"
            score   = 0 if match else 100
            flags   = [] if match else [
                f"Hash mismatch detected",
                f"Expected: {expected_hash}",
                f"Computed: {actual_hash}",
            ]

            findings = {
                "verdict": verdict,
                "integrity_verified": match,
                "trust_score": 100 - score,
                "expected_sha256": expected_hash,
                "computed_sha256": actual_hash,
                "file_size_bytes": len(content),
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                label = i18n.t("verdict_authentic", params.lang) if match else i18n.t("verdict_fake", params.lang)
                return f"{label} — SHA-256 {'MATCH' if match else 'MISMATCH'}"

            report = ForensicReporter.generate_report("verify_document_integrity", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_detect_ai_generated_text(mcp)
    register_analyze_file_metadata(mcp)
    register_verify_document_integrity(mcp)
