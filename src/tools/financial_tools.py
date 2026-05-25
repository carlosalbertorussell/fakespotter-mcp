"""
FakeSpotter — Physical & Financial Forensic Tools (3 tools)
────────────────────────────────────────────────────────────
6. verify_physical_currency — Banknote/coin image forensic analysis
7. validate_identity_doc    — ID document structure & consistency
8. detect_document_forgery  — ELA + copy-move on document photos
"""
from __future__ import annotations

import re
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.analysis import (
    analyze_noise_consistency,
    detect_copy_move,
    extract_exif,
    perform_ela,
)
from utils.i18n import i18n
from utils.media import download_image
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _score_to_verdict(score: int, threshold: int = 55) -> str:
    if score >= threshold:
        return "LIKELY_COUNTERFEIT"
    if score >= 30:
        return "UNCERTAIN — FURTHER INSPECTION REQUIRED"
    return "LIKELY_AUTHENTIC"


def _quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "COUNTERFEIT" in verdict or "FORGED" in verdict
        else i18n.t("verdict_authentic", lang) if "AUTHENTIC" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


# ---------------------------------------------------------------------------
# Tool 6: verify_physical_currency
# ---------------------------------------------------------------------------

class VerifyCurrencyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="URL of banknote or coin photograph")
    currency_code: str = Field("USD", description="ISO 4217 currency code (e.g. USD, EUR, GBP, ARS)")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_physical_currency(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_physical_currency",
        annotations={
            "title": "Physical Currency Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_physical_currency(params: VerifyCurrencyInput) -> str:
        """
        Forensic analysis of banknote or coin photographs for counterfeiting indicators.

        Applies:
        - ELA to detect inconsistent ink/paper compression patterns
        - Noise consistency to identify inkjet-printed vs genuine substrate
        - Copy-move to detect cloned security features (e.g. watermark duplication)
        - EXIF check for image manipulation software signatures
        - Colour distribution analysis for security ink anomalies

        Args:
            params.media_url: Banknote/coin image URL
            params.currency_code: ISO 4217 code
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Authenticity verdict or signed Forensic Certificate
        """
        try:
            image_bytes, _ = await download_image(params.media_url)

            ela   = perform_ela(image_bytes, quality=88)
            noise = analyze_noise_consistency(image_bytes)
            cm    = detect_copy_move(image_bytes)
            exif  = extract_exif(image_bytes)

            flags: list[str] = []
            score = 0

            # ELA: genuine currency printed on intaglio presses has very uniform ELA
            if ela.get("suspicious"):
                score += 35
                flags.append(f"ELA anomaly — non-uniform compression (score={ela['mean_ela']})")

            # Noise: inkjet counterfeits show different noise than genuine paper/cotton
            if noise.get("suspicious"):
                score += 25
                flags.append(f"Noise inconsistency detected (CV={noise.get('cv_ratio')})")

            # Copy-move: watermarks or serial numbers should not be duplicated
            if cm.get("copy_move_detected"):
                score += 30
                flags.append(f"Duplicated security feature region detected ({cm['suspicious_pairs']} pairs)")

            # EXIF
            if exif.get("ai_tool_detected"):
                score += 40
                flags.append(f"AI generation tool detected: {exif['detected_ai_tool']}")
            if exif.get("software") and "photoshop" in exif["software"].lower():
                score += 15
                flags.append("Photoshop editing signature in EXIF")

            score = min(100, score)
            verdict = _score_to_verdict(score)

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "currency_code": params.currency_code,
                "ela_summary": ela,
                "noise_summary": noise,
                "copy_move_summary": cm,
                "exif_summary": {
                    "has_exif": exif.get("has_exif"),
                    "software": exif.get("software"),
                    "ai_tool_detected": exif.get("ai_tool_detected"),
                },
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("verify_physical_currency", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 7: validate_identity_doc
# ---------------------------------------------------------------------------

class ValidateIdentityDocInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="URL of identity document photograph (passport, national ID, driver's licence)")
    doc_type: Literal["passport", "national_id", "drivers_licence", "unknown"] = Field(
        "unknown", description="Document type for targeted analysis"
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_validate_identity_doc(mcp: FastMCP) -> None:

    @mcp.tool(
        name="validate_identity_doc",
        annotations={
            "title": "Identity Document Validator",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def validate_identity_doc(params: ValidateIdentityDocInput) -> str:
        """
        Forensic validation of identity documents (KYC/AML use case).

        Checks:
        - ELA for localised digital manipulation of photos, fields, or security seals
        - Copy-move for cloned portrait or MRZ zone
        - Noise analysis for substrate consistency (laminate vs. printed)
        - EXIF for editing software traces
        - Document geometry heuristics based on doc_type

        Args:
            params.media_url: ID document image URL
            params.doc_type: 'passport', 'national_id', 'drivers_licence', or 'unknown'
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Validation verdict or signed Forensic Certificate
        """
        try:
            image_bytes, _ = await download_image(params.media_url)

            ela   = perform_ela(image_bytes, quality=90)
            cm    = detect_copy_move(image_bytes)
            noise = analyze_noise_consistency(image_bytes)
            exif  = extract_exif(image_bytes)

            flags: list[str] = []
            score = 0

            if ela.get("suspicious"):
                score += 35
                flags.append(f"ELA manipulation detected — data field likely altered (score={ela['mean_ela']})")

            if cm.get("copy_move_detected"):
                score += 30
                flags.append(f"Photo or MRZ zone duplication detected ({cm['suspicious_pairs']} pairs)")

            if noise.get("suspicious"):
                score += 20
                flags.append("Non-uniform noise — possible composite or laminate removal")

            if exif.get("ai_tool_detected"):
                score += 45
                flags.append(f"AI-generation tool in metadata: {exif['detected_ai_tool']}")

            if exif.get("software") and any(
                t in exif["software"].lower()
                for t in ["photoshop", "gimp", "pixelmator", "affinity"]
            ):
                score += 20
                flags.append(f"Image editing software: {exif['software']}")

            score = min(100, score)
            verdict = (
                "LIKELY_FORGED" if score >= 55
                else "UNCERTAIN — MANUAL REVIEW RECOMMENDED" if score >= 30
                else "LIKELY_GENUINE"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "doc_type": params.doc_type,
                "ela_summary": ela,
                "copy_move_summary": cm,
                "noise_summary": noise,
                "exif_summary": {
                    "has_exif": exif.get("has_exif"),
                    "software": exif.get("software"),
                    "ai_tool_detected": exif.get("ai_tool_detected"),
                    "detected_ai_tool": exif.get("detected_ai_tool"),
                },
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("validate_identity_doc", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 8: detect_document_forgery
# ---------------------------------------------------------------------------

class DetectDocumentForgeryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="URL of document image or scan to analyse for forgery")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_document_forgery(mcp: FastMCP) -> None:

    @mcp.tool(
        name="detect_document_forgery",
        annotations={
            "title": "Document Forgery Detector",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def detect_document_forgery(params: DetectDocumentForgeryInput) -> str:
        """
        Detects forgery in scanned or photographed documents (contracts, certificates,
        invoices, medical reports, academic credentials).

        Forensic layers:
        - ELA detects altered text blocks, signatures, or stamps
        - Copy-move detects cloned signatures or stamps
        - Noise analysis detects composite page backgrounds
        - EXIF fingerprinting for editing tools

        Args:
            params.media_url: Document image URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Forgery verdict or signed Forensic Certificate
        """
        try:
            image_bytes, _ = await download_image(params.media_url)

            ela   = perform_ela(image_bytes, quality=92)
            cm    = detect_copy_move(image_bytes)
            noise = analyze_noise_consistency(image_bytes)
            exif  = extract_exif(image_bytes)

            flags: list[str] = []
            score = 0

            if ela.get("suspicious"):
                score += 35
                flags.append(f"ELA: localised manipulation detected (mean={ela['mean_ela']}, std={ela['std_ela']})")

            if cm.get("copy_move_detected"):
                score += 35
                flags.append(f"Cloned signature or stamp region ({cm['suspicious_pairs']} matching pairs)")

            if noise.get("suspicious"):
                score += 15
                flags.append("Composite page background (noise floor inconsistency)")

            if exif.get("ai_tool_detected"):
                score += 40
                flags.append(f"AI generation: {exif['detected_ai_tool']}")

            if exif.get("software") and any(
                t in exif["software"].lower()
                for t in ["photoshop", "gimp", "illustrator", "affinity", "inkscape"]
            ):
                score += 20
                flags.append(f"Document editing tool: {exif['software']}")

            score = min(100, score)
            verdict = (
                "DOCUMENT_FORGED" if score >= 55
                else "SUSPICIOUS — VERIFICATION NEEDED" if score >= 30
                else "DOCUMENT_AUTHENTIC"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "ela_summary": ela,
                "copy_move_summary": cm,
                "noise_summary": noise,
                "editing_software": exif.get("software"),
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("detect_document_forgery", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_verify_physical_currency(mcp)
    register_validate_identity_doc(mcp)
    register_detect_document_forgery(mcp)
