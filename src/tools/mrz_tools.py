"""
FakeSpotter — tools/mrz_tools.py
MRZ (Machine Readable Zone) Validator (tool #23)

Validates the Machine Readable Zone of travel documents per ICAO Doc 9303.
Each field in the MRZ has a published checksum — if any digit was altered,
the checksum fails mathematically.

Supported document types:
  TD3 — Passports (2 × 44 chars)
  TD1 — ID cards, residence permits (3 × 30 chars)
  TD2 — Visas, official travel docs (2 × 36 chars)

Two input modes:
  1. mrz_lines: already-extracted MRZ text (no external deps required)
  2. image_url: document scan — extracts MRZ via passporteye (optional dep)

Checksum algorithm: ICAO Doc 9303 Part 3, Section 4.9
  Values: 0-9 → 0-9, A-Z → 10-35, < → 0
  Weights: cycling [7, 3, 1]
  Check digit = sum(value × weight) % 10

No external dependencies required for text input mode.
Optional dep: passporteye>=2.2,<3 (image mode only)
"""
from __future__ import annotations

import re
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# ICAO checksum algorithm
# ---------------------------------------------------------------------------

_CHAR_VALUES: dict[str, int] = {c: i + 10 for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}
_CHAR_VALUES.update({str(d): d for d in range(10)})
_CHAR_VALUES["<"] = 0
_WEIGHTS = [7, 3, 1]


def _check_digit(field: str) -> int:
    """Compute ICAO Doc 9303 check digit for a field string."""
    total = sum(_CHAR_VALUES.get(c, 0) * _WEIGHTS[i % 3] for i, c in enumerate(field))
    return total % 10


def _verify_field(field: str, check: str, label: str) -> tuple[bool, str]:
    """Verify a single MRZ field against its check digit."""
    if not check.isdigit():
        return False, f"{label}: check digit is not numeric ('{check}')"
    expected = _check_digit(field)
    actual   = int(check)
    if expected == actual:
        return True, f"{label}: ✓ checksum valid"
    return False, f"{label}: ✗ checksum FAILED (computed {expected}, found {actual})"


# ---------------------------------------------------------------------------
# MRZ parsers per document type
# ---------------------------------------------------------------------------

def _parse_td3(line1: str, line2: str) -> tuple[str, list[tuple[bool, str]], dict]:
    """Parse and validate TD3 (passport) MRZ — 2 × 44 chars."""
    if len(line1) != 44 or len(line2) != 44:
        return "FORMAT_INVALID", [
            (False, f"TD3 requires 2 × 44 chars, got {len(line1)} and {len(line2)}")
        ], {}

    checks: list[tuple[bool, str]] = []
    meta: dict = {}

    # Line 1
    meta["doc_type"]   = line1[0]
    meta["country"]    = line1[2:5].replace("<", "")
    name_raw           = line1[5:44]
    parts              = name_raw.split("<<", 1)
    meta["surname"]    = parts[0].replace("<", " ").strip()
    meta["given_names"]= parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    # Line 2 fields
    doc_number   = line2[0:9]
    doc_check    = line2[9]
    nationality  = line2[10:13].replace("<", "")
    dob          = line2[13:19]
    dob_check    = line2[19]
    sex          = line2[20]
    expiry       = line2[21:27]
    expiry_check = line2[27]
    optional     = line2[28:42]
    comp_check   = line2[42]

    meta["document_number"] = doc_number.replace("<", "")
    meta["nationality"]     = nationality
    meta["date_of_birth"]   = f"{dob[4:6]}/{dob[2:4]}/{'19' if int(dob[:2]) > 30 else '20'}{dob[:2]}"
    meta["sex"]             = {"M": "Male", "F": "Female", "<": "Unspecified"}.get(sex, sex)
    meta["expiry_date"]     = f"{expiry[4:6]}/{expiry[2:4]}/20{expiry[:2]}"

    # Validate checks
    checks.append(_verify_field(doc_number, doc_check, "Document number"))
    checks.append(_verify_field(dob, dob_check, "Date of birth"))
    checks.append(_verify_field(expiry, expiry_check, "Expiry date"))
    # Composite: doc number field (0-9) + optional (28-41) + DOB (13-19) + expiry (21-27) + optional (28-41)
    composite_field = line2[0:10] + line2[28:42] + line2[13:20] + line2[21:28] + line2[28:42]
    checks.append(_verify_field(composite_field, comp_check, "Composite check"))

    return "TD3_PASSPORT", checks, meta


def _parse_td1(line1: str, line2: str, line3: str) -> tuple[str, list[tuple[bool, str]], dict]:
    """Parse and validate TD1 (ID card) MRZ — 3 × 30 chars."""
    if len(line1) != 30 or len(line2) != 30 or len(line3) != 30:
        return "FORMAT_INVALID", [
            (False, f"TD1 requires 3 × 30 chars")
        ], {}

    checks: list[tuple[bool, str]] = []
    meta: dict = {}

    meta["doc_type"]  = line1[0]
    meta["country"]   = line1[2:5].replace("<", "")
    doc_number = line1[5:14]
    doc_check  = line1[14]
    meta["document_number"] = doc_number.replace("<", "")

    dob         = line2[0:6]
    dob_check   = line2[6]
    sex         = line2[7]
    expiry      = line2[8:14]
    expiry_check= line2[14]
    nationality = line2[15:18].replace("<", "")
    comp_check  = line2[29]

    meta["nationality"]     = nationality
    meta["sex"]             = {"M": "Male", "F": "Female", "<": "Unspecified"}.get(sex, sex)
    meta["date_of_birth"]   = f"{dob[4:6]}/{dob[2:4]}/{'19' if int(dob[:2]) > 30 else '20'}{dob[:2]}"
    meta["expiry_date"]     = f"{expiry[4:6]}/{expiry[2:4]}/20{expiry[:2]}"

    name_raw = line3
    parts = name_raw.split("<<", 1)
    meta["surname"]     = parts[0].replace("<", " ").strip()
    meta["given_names"] = parts[1].replace("<", " ").strip() if len(parts) > 1 else ""

    checks.append(_verify_field(doc_number, doc_check, "Document number"))
    checks.append(_verify_field(dob, dob_check, "Date of birth"))
    checks.append(_verify_field(expiry, expiry_check, "Expiry date"))
    composite = line1[5:30] + line2[0:7] + line2[8:15] + line2[18:29]
    checks.append(_verify_field(composite, comp_check, "Composite check"))

    return "TD1_ID_CARD", checks, meta


def _detect_and_parse(lines: list[str]) -> tuple[str, list[tuple[bool, str]], dict]:
    """Auto-detect document type from MRZ lines and parse."""
    lines = [l.strip().upper() for l in lines if l.strip()]
    if len(lines) == 2 and all(len(l) == 44 for l in lines):
        return _parse_td3(lines[0], lines[1])
    if len(lines) == 3 and all(len(l) == 30 for l in lines):
        return _parse_td1(lines[0], lines[1], lines[2])
    lengths = [len(l) for l in lines]
    return "FORMAT_INVALID", [
        (False, f"Unrecognized MRZ format: {len(lines)} lines of lengths {lengths}. "
                f"Expected: TD3 (2×44), TD1 (3×30)")
    ], {}


# ---------------------------------------------------------------------------
# Tool: validate_mrz
# ---------------------------------------------------------------------------

class ValidateMRZInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    mrz_lines: list[str] = Field(
        default=[],
        description=(
            "MRZ lines as a list of strings. "
            "TD3 passport: 2 strings of 44 chars each. "
            "TD1 ID card: 3 strings of 30 chars each. "
            "Use '<' for filler characters as printed on the document."
        ),
        max_length=3,
    )
    image_url: str = Field(
        "",
        description=(
            "Optional. URL of a document scan (JPEG/PNG). "
            "FakeSpotter will extract the MRZ via OCR (requires passporteye). "
            "Use mrz_lines for validated text input — more reliable."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_validate_mrz(mcp: FastMCP) -> None:

    @mcp.tool(
        name="validate_mrz",
        annotations={
            "title": "MRZ Validator",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def validate_mrz(params: ValidateMRZInput) -> str:
        """
        Validates the Machine Readable Zone (MRZ) of travel documents
        per ICAO Doc 9303 (passports, ID cards, visas).

        Each field in the MRZ has a published check digit computed with
        the ICAO weighted-mod-10 algorithm. If any digit was altered,
        the checksum fails mathematically — 0% FP/FN by construction.

        Validated fields (per document type):
          TD3 Passport:  Document number, Date of birth, Expiry date, Composite
          TD1 ID Card:   Document number, Date of birth, Expiry date, Composite

        Extracted metadata:
          Surname, given names, nationality, document number,
          date of birth, sex, expiry date, document type.

        Input modes:
          mrz_lines: pre-extracted MRZ text (recommended, no external deps)
          image_url: document scan — requires passporteye (optional dep)

        Verdicts:
          MRZ_VALID          — all checksums pass
          MRZ_CHECKSUM_FAILED — one or more fields have incorrect check digits
          MRZ_FORMAT_INVALID — lines do not match any known MRZ format

        Args:
            params.mrz_lines:  List of MRZ line strings
            params.image_url:  Optional document scan URL (OCR extraction)
            params.lang:       en | es
            params.report_mode: quick | full
        """
        try:
            flags: list[str] = []
            lines: list[str] = []

            if params.mrz_lines:
                lines = [l.strip().upper() for l in params.mrz_lines if l.strip()]
                flags.append("Input mode: pre-extracted MRZ text")

            elif params.image_url:
                # OCR extraction via passporteye
                flags.append("Input mode: image OCR (passporteye)")
                try:
                    from passporteye import read_mrz
                    import tempfile, pathlib

                    async with httpx.AsyncClient(follow_redirects=True, timeout=30,
                        headers={"User-Agent": "FakeSpotter/1.0 mrz-validator"}) as client:
                        resp = await client.get(params.image_url)
                        resp.raise_for_status()
                        img_bytes = resp.content

                    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
                        f.write(img_bytes)
                        tmp_path = f.name

                    mrz = read_mrz(tmp_path)
                    pathlib.Path(tmp_path).unlink(missing_ok=True)

                    if mrz is None:
                        return "[FakeSpotter] MRZ_NOT_FOUND: no MRZ detected in the image"
                    lines = [mrz.aux.get("mrz_type", ""), *mrz.to_mrz().splitlines()]
                    lines = [l for l in lines if l and re.fullmatch(r"[A-Z0-9<]+", l)]

                except ImportError:
                    return (
                        "[FakeSpotter Error] passporteye not installed — cannot process image. "
                        "Install with: pip install passporteye>=2.2,<3 "
                        "OR provide MRZ text directly via mrz_lines parameter."
                    )
            else:
                return "[FakeSpotter Error] Provide either mrz_lines or image_url."

            if not lines:
                return "[FakeSpotter Error] No MRZ lines to validate."

            # Parse and validate
            doc_type, checks, meta = _detect_and_parse(lines)

            failed  = [msg for ok, msg in checks if not ok]
            passed  = [msg for ok, msg in checks if ok]
            all_ok  = len(failed) == 0 and doc_type != "FORMAT_INVALID"

            for msg in passed:
                flags.append(msg)
            for msg in failed:
                flags.append(msg)

            if doc_type == "FORMAT_INVALID":
                verdict = "MRZ_FORMAT_INVALID"
                trust   = 0
            elif all_ok:
                verdict = "MRZ_VALID"
                trust   = 100
            else:
                verdict = "MRZ_CHECKSUM_FAILED"
                trust   = 0

            findings = {
                "verdict":          verdict,
                "trust_score":      trust,
                "document_type":    doc_type,
                "checksums_passed": len(passed),
                "checksums_failed": len(failed),
                "metadata":         meta,
                "forensic_flags":   flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "MRZ_VALID"
                    else i18n.t("verdict_fake", params.lang)
                )
                name = f"{meta.get('surname','')} {meta.get('given_names','')}".strip()
                country = meta.get("country", "?")
                return (
                    f"{label} ({trust}/100) — {verdict} [{doc_type}] | "
                    f"{name}, {country} | "
                    f"{len(passed)}/{len(checks)} checksums passed"
                )

            report = ForensicReporter.generate_report("validate_mrz", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_validate_mrz(mcp)
