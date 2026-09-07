"""
FakeSpotter — tools/qr_tools.py
QR Code Forensic Inspector (tool #20)

Detects and decodes QR codes in images and PDFs.
Extends Invoice Guard: verifies that the QR code in a supplier invoice
points to the expected account number, URL, or payment data.

Supported input formats:
  Images: JPEG, PNG, WebP, BMP, TIFF
  Documents: PDF (all pages rasterized at 150 DPI via PyMuPDF)

Dependencies:
  opencv-python-headless (already in requirements)
  pymupdf>=1.24,<2 (added in S11)
"""
from __future__ import annotations

import re
from typing import Literal

import cv2
import httpx
import numpy as np
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# QR content type detection
# ---------------------------------------------------------------------------

def _classify_content(data: str) -> tuple[str, dict]:
    """Classify the decoded QR content and extract structured fields."""
    stripped = data.strip()

    # URL
    if re.match(r"^https?://", stripped, re.I):
        return "URL", {"url": stripped}

    # CBU / CVU (Argentina) — exactly 22 digits
    if re.fullmatch(r"\d{22}", stripped):
        prefix = stripped[:3]
        kind = "CVU" if prefix in ("000",) else "CBU"
        return kind, {kind.lower(): stripped, "bank_code": stripped[:3], "account": stripped[3:]}

    # CLABE (Mexico) — exactly 18 digits
    if re.fullmatch(r"\d{18}", stripped):
        return "CLABE", {"clabe": stripped, "bank_code": stripped[:3], "city_code": stripped[3:6]}

    # IBAN — 2-letter country + 2 check digits + up to 30 alphanumeric
    if re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{4,30}", stripped.upper()):
        return "IBAN", {"iban": stripped.upper(), "country": stripped[:2].upper()}

    # EMV/PIX payment string (Brazil) — starts with known EMV payload IDs
    if stripped.startswith("00020126") or stripped.startswith("000201"):
        return "PIX_EMV", {"payload": stripped[:40] + "…" if len(stripped) > 40 else stripped}

    # vCard
    if stripped.upper().startswith("BEGIN:VCARD"):
        return "VCARD", {"raw": stripped[:100]}

    # Generic text
    return "TEXT", {"content": stripped}


# ---------------------------------------------------------------------------
# QR detection on image bytes
# ---------------------------------------------------------------------------

def _decode_from_image_bytes(img_bytes: bytes) -> list[str]:
    """Run OpenCV QR decoder on raw image bytes. Returns list of decoded strings."""
    arr = np.frombuffer(img_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return []

    detector = cv2.QRCodeDetector()

    # Try multi-QR first (catches grids and invoices with multiple codes)
    try:
        retval, decoded_list, points_list, _ = detector.detectAndDecodeMulti(img)
        if retval and decoded_list:
            return [d for d in decoded_list if d]
    except Exception:
        pass

    # Fallback: single QR
    try:
        data, _, _ = detector.detectAndDecode(img)
        if data:
            return [data]
    except Exception:
        pass

    return []


def _decode_from_pdf(pdf_bytes: bytes, max_pages: int = 10) -> list[tuple[int, str]]:
    """Rasterize each PDF page and scan for QR codes. Returns [(page, data), ...]."""
    import fitz  # PyMuPDF

    results: list[tuple[int, str]] = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")

    for page_num in range(min(len(doc), max_pages)):
        page = doc[page_num]
        # 150 DPI — enough for QR detection without excessive memory
        mat = fitz.Matrix(150 / 72, 150 / 72)
        pix = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB)
        img_bytes = pix.tobytes("jpeg")
        decoded = _decode_from_image_bytes(img_bytes)
        for d in decoded:
            results.append((page_num + 1, d))

    doc.close()
    return results


# ---------------------------------------------------------------------------
# Comparison helper
# ---------------------------------------------------------------------------

def _compare(found: str, expected: str) -> bool:
    """Case-insensitive, whitespace-normalised comparison."""
    return found.strip().lower() == expected.strip().lower()


# ---------------------------------------------------------------------------
# Tool: inspect_qr_code
# ---------------------------------------------------------------------------

class InspectQRCodeInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url: str = Field(
        ...,
        description=(
            "Public URL of the file to inspect. "
            "Supported: JPEG, PNG, WebP, BMP (images) and PDF (all pages scanned). "
            "Typical use: supplier invoice PDF or screenshot."
        ),
    )
    expected_data: str = Field(
        "",
        description=(
            "Optional. The exact value you expect the QR code to contain "
            "(e.g. a CBU number, IBAN, URL). "
            "If provided, returns QR_MATCH or QR_MISMATCH. "
            "If omitted, returns QR_DECODED with the raw content."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_inspect_qr_code(mcp: FastMCP) -> None:

    @mcp.tool(
        name="inspect_qr_code",
        annotations={
            "title": "QR Code Inspector",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def inspect_qr_code(params: InspectQRCodeInput) -> str:
        """
        Detects and decodes QR codes in images and PDF documents.

        Primary use case — Invoice Guard extension:
          A supplier invoice may pass SHA-256 integrity checks but contain
          a QR code pointing to a fraudulent bank account. This tool decodes
          the QR and optionally compares it against the expected value.

        Supported content types auto-detected:
          URL, CBU (Argentina), CVU (Argentina), CLABE (Mexico),
          IBAN (SEPA), PIX/EMV (Brazil), vCard, plain text.

        With expected_data:
          Returns QR_MATCH (deterministic, 0% FP/FN) or QR_MISMATCH.

        Without expected_data:
          Returns QR_DECODED with the raw content for human review.

        Args:
            params.file_url:     Image or PDF URL
            params.expected_data: Expected QR content for comparison (optional)
            params.lang:         en | es
            params.report_mode:  quick | full
        """
        try:
            flags: list[str] = []

            # Download
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 qr-inspector"},
            ) as client:
                resp = await client.get(params.file_url)
                resp.raise_for_status()
                file_bytes = resp.content
                content_type = resp.headers.get("content-type", "").lower()

            # Detect format from magic bytes
            is_pdf = (
                file_bytes[:4] == b"%PDF"
                or "pdf" in content_type
                or params.file_url.lower().endswith(".pdf")
            )

            # Decode QR
            if is_pdf:
                try:
                    raw_results = _decode_from_pdf(file_bytes)
                    qr_list = [(f"page {p}", d) for p, d in raw_results]
                    flags.append(f"PDF scanned ({len(set(p for p,_ in raw_results))} pages with QR)")
                except ImportError:
                    return (
                        "[FakeSpotter Error] PyMuPDF not installed. "
                        "Add pymupdf>=1.24,<2 to requirements.txt."
                    )
            else:
                decoded = _decode_from_image_bytes(file_bytes)
                qr_list = [("image", d) for d in decoded]

            if not qr_list:
                verdict = "NO_QR_FOUND"
                score   = 0
                flags.append("No QR code detected in the file")
                findings = {
                    "verdict": verdict,
                    "trust_score": 50,
                    "qr_codes_found": 0,
                    "forensic_flags": flags,
                }
                if params.report_mode == "quick":
                    label = i18n.t("verdict_uncertain", params.lang)
                    return f"{label} — NO_QR_FOUND: no QR code detected"
                report = ForensicReporter.generate_report("inspect_qr_code", findings, params.lang)
                return ForensicReporter.format_certificate(report, findings)

            # Parse first QR (most invoices have one)
            location, raw_data = qr_list[0]
            content_type_label, parsed = _classify_content(raw_data)
            flags.append(f"QR type detected: {content_type_label} (at {location})")
            if len(qr_list) > 1:
                flags.append(f"Multiple QR codes found: {len(qr_list)} total")

            # Verdict
            if params.expected_data:
                match = _compare(raw_data, params.expected_data)
                verdict = "QR_MATCH" if match else "QR_MISMATCH"
                score   = 0 if match else 100
                trust   = 100 if match else 0
                if not match:
                    flags.append(f"Expected: {params.expected_data.strip()}")
                    flags.append(f"Found:    {raw_data.strip()}")
            else:
                verdict = "QR_DECODED"
                score   = 0
                trust   = 100

            findings = {
                "verdict":        verdict,
                "trust_score":    trust,
                "qr_codes_found": len(qr_list),
                "qr_content_raw": raw_data,
                "qr_content_type": content_type_label,
                "qr_parsed":      parsed,
                "all_qr_codes":   [{"location": loc, "data": d} for loc, d in qr_list],
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "QR_MATCH"
                    else i18n.t("verdict_fake", params.lang) if verdict == "QR_MISMATCH"
                    else i18n.t("verdict_uncertain", params.lang)
                )
                flag_str = " | ".join(flags) if flags else i18n.t("no_flags", params.lang)
                return f"{label} ({trust}/100) — {verdict}: {raw_data[:80]} | {flag_str}"

            report = ForensicReporter.generate_report("inspect_qr_code", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_inspect_qr_code(mcp)
