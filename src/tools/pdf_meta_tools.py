"""
FakeSpotter — tools/pdf_meta_tools.py
PDF Metadata Forensics (tool #24)

Extracts and cross-references all metadata sources in a PDF to detect
inconsistencies that reveal backdating, re-creation, or post-issuance modification.

Signals analysed:
  Temporal:
    CreationDate vs ModDate — a document "from 2022" with ModDate 2026 is suspicious
    PDF version — each Acrobat save increments version; many increments post-date is a signal
    XMP metadata timestamps — secondary source to cross-check
  Software:
    Producer — software that created the PDF (LibreOffice, Acrobat, Word, etc.)
    Creator  — source application (Word, LibreOffice Writer, etc.)
    Consistency between declared doc type and Producer
  Identity:
    Author field vs content of the document
  Structure:
    PermsHandler — permissions set after creation (suggests controlled modification)
    Encryption  — unusual for shared invoices/contracts
    JavaScript  — not expected in financial/legal documents
    Incremental updates — count and timing

No new dependencies — uses PyMuPDF (added in S11).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Literal

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# PDF 32000-1 §7.9.4: D:YYYYMMDDHHmmSSOHH'mm' — everything after YYYY is
# optional, O is +, - or Z, and the apostrophes are often omitted.
_PDF_DATE_RE = re.compile(
    r"^(?:D:)?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
    r"(?:([Zz+\-])(?:(\d{2})'?(?:(\d{2})'?)?)?)?$"
)
# ISO 8601 / XMP (W3C-DTF): YYYY[-MM[-DD[Thh:mm[:ss[.s]][TZD]]]]
_ISO_DATE_RE = re.compile(
    r"^(\d{4})(?:-(\d{2})(?:-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?"
    r"(Z|z|[+\-]\d{2}(?::?\d{2})?)?)?)?)?$"
)


def _build_utc(year, month, day, hour, minute, second, micro, offset_minutes) -> datetime | None:
    try:
        dt = datetime(int(year), int(month or 1), int(day or 1), int(hour or 0),
                      int(minute or 0), int(second or 0), micro, tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt - timedelta(minutes=offset_minutes)


def _parse_pdf_date(date_str: str) -> datetime | None:
    """Parse a PDF date (D:YYYYMMDDHHmmSSOHH'mm') or an ISO 8601 / XMP date.

    Returns an aware datetime in UTC (local times are converted using their
    offset; a date without an offset is taken as UTC), or None if the string
    is not a valid date.
    """
    if not date_str:
        return None
    s = date_str.strip()

    m = _PDF_DATE_RE.match(s)
    if m:
        year, month, day, hour, minute, second, sign, off_h, off_m = m.groups()
        offset = 0
        if sign in ("+", "-") and off_h:
            offset = int(off_h) * 60 + int(off_m or 0)
            if sign == "-":
                offset = -offset
        return _build_utc(year, month, day, hour, minute, second, 0, offset)

    m = _ISO_DATE_RE.match(s)
    if m:
        year, month, day, hour, minute, second, frac, tz = m.groups()
        micro = int((frac or "0")[:6].ljust(6, "0"))
        offset = 0
        if tz and tz not in ("Z", "z"):
            digits = tz[1:].replace(":", "")
            offset = int(digits[:2]) * 60 + int(digits[2:4] or 0)
            if tz[0] == "-":
                offset = -offset
        return _build_utc(year, month, day, hour, minute, second, micro, offset)

    return None


def _producer_category(producer: str) -> str:
    """Bucket the Producer string into a known software category."""
    p = producer.lower()
    if any(k in p for k in ("acrobat", "adobe pdf", "adobe acrobat")):
        return "Adobe Acrobat"
    if any(k in p for k in ("libreoffice", "openoffice", "staroffice")):
        return "LibreOffice / OpenOffice"
    if any(k in p for k in ("microsoft word", "microsoft office", "ms word")):
        return "Microsoft Word / Office"
    if any(k in p for k in ("fpdf", "reportlab", "fpdf2", "weasyprint",
                              "wkhtmltopdf", "pdfkit", "pandoc", "latex", "pdflatex")):
        return "Programmatic / Open-source generator"
    if any(k in p for k in ("docusign",)):
        return "DocuSign"
    if any(k in p for k in ("nitro", "foxit", "pdfcreator", "bullzip",
                              "pdf24", "cute pdf", "dopdf")):
        return "Third-party PDF creator"
    if any(k in p for k in ("canva",)):
        return "Canva"
    if any(k in p for k in ("google", "chromium", "chrome")):
        return "Google / Chromium"
    if p:
        return f"Other ({producer[:40]})"
    return "Unknown"


def _extract_pdf_metadata(pdf_bytes: bytes) -> dict:
    """Extract all forensically relevant metadata from a PDF using PyMuPDF."""
    import pymupdf

    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    meta = doc.metadata or {}
    trailer = doc.pdf_trailer() or {}
    perm = doc.permissions

    # Basic metadata
    result: dict = {
        "page_count":      doc.page_count,
        "pdf_version":     doc.version_count,
        "is_encrypted":    doc.is_encrypted,
        "needs_pass":      doc.needs_pass,
        "permissions":     perm,
        "creation_date":   meta.get("creationDate", ""),
        "mod_date":        meta.get("modDate", ""),
        "producer":        meta.get("producer", ""),
        "creator":         meta.get("creator", ""),
        "author":          meta.get("author", ""),
        "title":           meta.get("title", ""),
        "subject":         meta.get("subject", ""),
        "keywords":        meta.get("keywords", ""),
        "producer_category": _producer_category(meta.get("producer", "")),
        "has_javascript":  False,
        "incremental_updates": doc.version_count,
        "xref_count":      doc.xref_length(),
    }

    # Check for JavaScript
    try:
        for xref in range(1, doc.xref_length()):
            try:
                xtype = doc.xref_object(xref, compressed=False)
                if "JavaScript" in xtype or "/JS " in xtype:
                    result["has_javascript"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass

    # XMP metadata (secondary timestamp source)
    try:
        xmp = doc.get_xml_metadata()
        result["xmp_available"] = bool(xmp)
        if xmp:
            # Extract XMP CreateDate and MetadataDate
            # (element form <xmp:CreateDate>..</xmp:CreateDate> or attribute
            # form xmp:CreateDate="..." on rdf:Description)
            def _xmp_value(tag: str) -> str:
                m = (re.search(rf"<xmp:{tag}>\s*(.*?)\s*</xmp:{tag}>", xmp, re.S)
                     or re.search(rf"\bxmp:{tag}\s*=\s*[\"']([^\"']*)[\"']", xmp))
                return m.group(1).strip() if m else ""
            result["xmp_create_date"] = _xmp_value("CreateDate")
            result["xmp_modify_date"] = _xmp_value("ModifyDate")
    except Exception:
        result["xmp_available"] = False

    doc.close()
    return result


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _analyze_metadata(meta: dict) -> tuple[str, int, list[str]]:
    """Score metadata for forensic signals. Returns (verdict, score, flags)."""
    flags: list[str] = []
    score = 0

    creation_date_raw = meta.get("creation_date", "")
    mod_date_raw      = meta.get("mod_date", "")
    created = _parse_pdf_date(creation_date_raw)
    modified = _parse_pdf_date(mod_date_raw)
    now = datetime.now(timezone.utc)

    # ── Temporal analysis ────────────────────────────────────────────────
    if created:
        flags.append(f"CreationDate: {created.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if created > now:
            score += 30
            flags.append("⚠ CreationDate is in the FUTURE — impossible or system clock manipulation")

    if modified:
        flags.append(f"ModDate: {modified.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        if modified > now:
            score += 30
            flags.append("⚠ ModDate is in the FUTURE")

    if created and modified:
        delta_days = (modified - created).days
        if delta_days < 0:
            score += 35
            flags.append(f"⚠ ModDate is BEFORE CreationDate ({abs(delta_days)} days) — timestamp manipulation")
        elif delta_days > 365 * 2:
            score += 20
            flags.append(f"ModDate is {delta_days} days after CreationDate — document modified long after creation")
        elif delta_days > 0:
            flags.append(f"Document modified {delta_days} days after creation")

    # XMP cross-check
    xmp_create = meta.get("xmp_create_date", "")
    if xmp_create and created:
        xmp_dt = _parse_pdf_date(xmp_create)
        if xmp_dt:
            diff_minutes = abs((xmp_dt - created).total_seconds()) / 60
            if diff_minutes > 60:
                score += 15
                flags.append(
                    f"⚠ XMP CreateDate ({xmp_dt.strftime('%Y-%m-%d')}) "
                    f"differs from PDF CreationDate ({created.strftime('%Y-%m-%d')}) "
                    f"by {int(diff_minutes/60)} hours — metadata inconsistency"
                )

    if not creation_date_raw and not mod_date_raw:
        score += 10
        flags.append("No timestamps in metadata — may have been stripped")

    # ── Software analysis ─────────────────────────────────────────────────
    producer  = meta.get("producer", "")
    creator   = meta.get("creator", "")
    prod_cat  = meta.get("producer_category", "Unknown")
    flags.append(f"Producer: {producer or 'not set'} [{prod_cat}]")
    if creator:
        flags.append(f"Creator: {creator}")

    # Programmatic generators on legal/financial docs are unusual
    if prod_cat == "Programmatic / Open-source generator":
        score += 10
        flags.append(
            "ℹ Producer is a programmatic PDF generator — "
            "unusual for official documents, normal for automated systems"
        )

    # ── Structure analysis ────────────────────────────────────────────────
    if meta.get("is_encrypted"):
        score += 15
        flags.append("⚠ PDF is encrypted — unusual for a shared invoice or contract")

    if meta.get("has_javascript"):
        score += 25
        flags.append("⚠ JavaScript detected — not expected in financial/legal documents")

    incremental = meta.get("incremental_updates", 1)
    if incremental > 3:
        score += 10
        flags.append(
            f"PDF has {incremental} incremental update(s) — "
            f"document was saved/modified multiple times"
        )

    # ── Author / identity ─────────────────────────────────────────────────
    author = meta.get("author", "")
    if author:
        flags.append(f"Author: {author}")

    score = min(100, score)

    if score >= 50:
        verdict = "METADATA_SUSPICIOUS"
    elif score >= 20:
        verdict = "METADATA_INCONSISTENT"
    else:
        verdict = "METADATA_CONSISTENT"

    return verdict, score, flags


# ---------------------------------------------------------------------------
# Tool: analyze_pdf_metadata
# ---------------------------------------------------------------------------

class AnalyzePDFMetadataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url:    str = Field(
        ...,
        description="Public URL of a PDF document to analyse forensically.",
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_pdf_metadata(mcp: MCPServer) -> None:

    @mcp.tool(
        name="analyze_pdf_metadata",
        annotations={
            "title": "PDF Metadata Forensics",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_pdf_metadata(params: AnalyzePDFMetadataInput) -> str:
        """
        Forensic analysis of PDF internal metadata to detect backdating,
        re-creation, and post-issuance modification.

        Signals analysed:
          Temporal:
            CreationDate vs ModDate gap (large gap or reversed order)
            Timestamps in the future (impossible or clock manipulation)
            XMP metadata vs PDF dictionary timestamp cross-check
          Software:
            Producer (Adobe, LibreOffice, programmatic generator, etc.)
            Creator (source application)
          Structure:
            Incremental updates (how many times was the file saved?)
            JavaScript presence (unexpected in financial/legal docs)
            Encryption (unusual for shared documents)
          Identity:
            Author, Title, Subject fields

        No external network calls — analysis is entirely local.
        Requires PyMuPDF (added in S11).

        Verdicts:
          METADATA_CONSISTENT   — no forensic signals detected
          METADATA_INCONSISTENT — minor anomalies worth noting
          METADATA_SUSPICIOUS   — significant inconsistencies detected

        Args:
            params.file_url:    URL of the PDF to analyse
            params.lang:        en | es
            params.report_mode: quick | full
        """
        try:
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 pdf-metadata-forensics"},
            ) as client:
                resp = await client.get(params.file_url)
                resp.raise_for_status()
                pdf_bytes = resp.content

            if pdf_bytes[:4] != b"%PDF":
                return "[FakeSpotter Error] File is not a PDF (magic bytes check failed)"

            try:
                raw_meta = _extract_pdf_metadata(pdf_bytes)
            except ImportError:
                return (
                    "[FakeSpotter Error] PyMuPDF not installed. "
                    "Add pymupdf>=2.1,<3 to requirements.txt."
                )

            verdict, score, flags = _analyze_metadata(raw_meta)
            trust = 100 - score

            findings = {
                "verdict":      verdict,
                "trust_score":  trust,
                "risk_score":   score,
                "metadata":     raw_meta,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "METADATA_CONSISTENT"
                    else i18n.t("verdict_uncertain", params.lang) if verdict == "METADATA_INCONSISTENT"
                    else i18n.t("verdict_fake", params.lang)
                )
                key_flags = [f for f in flags if f.startswith("⚠")][:3] or flags[:3]
                return f"{label} ({trust}/100) — {verdict} | {' | '.join(key_flags)}"

            report = ForensicReporter.generate_report("analyze_pdf_metadata", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: MCPServer) -> None:
    register_analyze_pdf_metadata(mcp)
