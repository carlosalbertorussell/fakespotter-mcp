"""
FakeSpotter — tools/timestamp_tools.py
RFC 3161 Trusted Timestamp Verifier (tool #28)

Verifies RFC 3161 timestamp tokens (TST) issued by a Timestamp Authority (TSA).
A trusted timestamp cryptographically proves that a document existed at a
specific point in time, independently of the document signer.

Use cases:
  - Verify that a contract was timestamped before a disputed date
  - Confirm a receipt existed before a transaction was contested
  - Validate the timestamp on a digitally signed PDF
  - Check a standalone .tsr file accompanying a document

Input modes:
  1. pdf_url:    Extracts embedded timestamp tokens from a signed PDF
  2. tsr_url:    Raw RFC 3161 Timestamp Response (.tsr) file
  3. tsr_hex:    Hex-encoded timestamp token for inline verification

What is verified:
  - TSA certificate chain of trust
  - TSA certificate validity (not expired at signing time)
  - Timestamp token integrity (tamper detection)
  - Message Imprint: the hash algorithm and document digest covered
  - TSA policy OID
  - Trusted time (from the TSA, not the signer's clock)

Verdicts:
  TIMESTAMP_VALID     — token intact, TSA trusted, certificate valid
  TIMESTAMP_INVALID   — token tampered or TSA signature invalid
  TIMESTAMP_EXPIRED   — TSA certificate expired at time of stamping
  NO_TIMESTAMP_FOUND  — no embedded timestamp in the document

Dependency: pyhanko (already in requirements from S12)
"""
from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Timestamp extraction and verification
# ---------------------------------------------------------------------------

def _verify_tsr_bytes(tsr_bytes: bytes) -> dict:
    """
    Verify an RFC 3161 timestamp response using pyhanko.
    Returns a dict with verdict, time, TSA info, and any errors.
    """
    from pyhanko.sign.timestamps import HTTPTimeStamper
    from pyhanko.sign.validation import validate_tst_signed_data
    from pyhanko_certvalidator.context import ValidationContext
    from asn1crypto import tsp, core, cms

    result: dict = {
        "valid":          False,
        "trusted_time":   None,
        "tsa_name":       "",
        "hash_algorithm": "",
        "message_imprint_hex": "",
        "policy_oid":     "",
        "serial_number":  "",
        "error":          "",
    }

    try:
        # Parse the TimeStampResponse
        tst_response = tsp.TimeStampResp.load(tsr_bytes)
        status = tst_response["status"]["status"].native
        if status != "granted":
            result["error"] = f"TSA returned status: {status}"
            return result

        tst_info_bytes = tst_response["time_stamp_token"]["content"]["encap_content_info"]\
            ["content"].parsed.contents

        # Parse TSTInfo
        tst_info = tsp.TSTInfo.load(tst_info_bytes)
        gen_time = tst_info["gen_time"].native
        if isinstance(gen_time, datetime):
            if gen_time.tzinfo is None:
                gen_time = gen_time.replace(tzinfo=timezone.utc)
            result["trusted_time"] = gen_time.isoformat()
        result["policy_oid"]  = str(tst_info["policy"].native)
        result["serial_number"] = str(tst_info["serial_number"].native)

        # Message imprint
        msg_imprint = tst_info["message_imprint"]
        result["hash_algorithm"] = msg_imprint["hash_algorithm"]["algorithm"].native
        result["message_imprint_hex"] = msg_imprint["hashed_message"].native.hex()

        # TSA name from signer info
        signed_data = tst_response["time_stamp_token"]["content"]
        signer_infos = signed_data["signer_infos"]
        if signer_infos:
            # Get certificate from included certs
            certs = signed_data["certificates"]
            if certs:
                cert = certs[0].chosen
                subject = cert.subject
                result["tsa_name"] = subject.human_friendly

        # Validate signature
        vc = ValidationContext(allow_fetching=True)
        status_obj = validate_tst_signed_data(
            tst_response["time_stamp_token"]["content"], vc
        )
        result["valid"]   = bool(status_obj.intact and status_obj.valid)
        if not status_obj.intact:
            result["error"] = "Timestamp token integrity check failed — token may be tampered"
        elif not status_obj.valid:
            result["error"] = "TSA certificate chain validation failed"

    except ImportError:
        result["error"] = "asn1crypto or pyhanko not available"
    except Exception as exc:
        result["error"] = str(exc)[:300]

    return result


def _extract_timestamps_from_pdf(pdf_bytes: bytes) -> list[bytes]:
    """Extract RFC 3161 timestamp tokens embedded in a signed PDF."""
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature

    tsr_list: list[bytes] = []
    doc = PdfFileReader(io.BytesIO(pdf_bytes))

    for sig in doc.embedded_signatures:
        try:
            # Check for document timestamp (LTV/DSS embedded TST)
            if hasattr(sig, "attached_timestamp_data") and sig.attached_timestamp_data:
                tsr_list.append(bytes(sig.attached_timestamp_data))
            # Check for signature timestamp attribute
            if hasattr(sig, "external_timestamp") and sig.external_timestamp:
                tsr_list.append(bytes(sig.external_timestamp))
        except Exception:
            pass

    return tsr_list


# ---------------------------------------------------------------------------
# Tool: verify_rfc3161_timestamp
# ---------------------------------------------------------------------------

class VerifyRFC3161TimestampInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    pdf_url: str = Field(
        "",
        description=(
            "Public URL of a signed PDF. FakeSpotter will extract and verify "
            "all embedded RFC 3161 timestamp tokens."
        ),
    )
    tsr_url: str = Field(
        "",
        description=(
            "Public URL of a raw RFC 3161 Timestamp Response file (.tsr). "
            "Used when the timestamp accompanies the document as a separate file."
        ),
    )
    tsr_hex: str = Field(
        "",
        description=(
            "Hex-encoded RFC 3161 Timestamp Response for inline verification. "
            "Useful when the token is embedded in another system."
        ),
    )
    document_hash: str = Field(
        "",
        description=(
            "Optional. SHA-256 hash (hex) of the original document. "
            "When provided, FakeSpotter verifies that the timestamp covers this exact document."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_rfc3161_timestamp(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_rfc3161_timestamp",
        annotations={
            "title": "RFC 3161 Timestamp Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_rfc3161_timestamp(params: VerifyRFC3161TimestampInput) -> str:
        """
        Verifies RFC 3161 trusted timestamp tokens issued by a Timestamp Authority.

        A trusted timestamp proves a document existed at a specific time,
        independently of the document signer. This is stronger than the
        signer's clock: the TSA is a neutral third party whose time is
        cryptographically bound to the token.

        Verified fields:
          - Token integrity (tamper detection via signature)
          - TSA certificate chain of trust
          - TSA certificate validity at signing time
          - Trusted generation time (from TSA, not signer clock)
          - Message Imprint: hash algorithm + document digest covered
          - Optional: whether the token covers a specific document hash

        Input modes (provide one):
          pdf_url:   signed PDF — timestamps extracted automatically
          tsr_url:   raw .tsr file URL
          tsr_hex:   hex-encoded timestamp token

        Verdicts:
          TIMESTAMP_VALID     — token intact, TSA trusted
          TIMESTAMP_INVALID   — tampered token or invalid TSA chain
          TIMESTAMP_EXPIRED   — TSA certificate expired at stamping time
          NO_TIMESTAMP_FOUND  — no embedded timestamp in the document

        Requires: pyhanko (already in requirements from S12)
        """
        try:
            import pyhanko  # noqa — trigger ImportError if missing
        except ImportError:
            return "[FakeSpotter Error] pyhanko not installed. Add pyhanko>=0.37.0,<1 to requirements.txt."

        flags:  list[str] = []
        tokens: list[bytes] = []

        async with httpx.AsyncClient(
            follow_redirects=True, timeout=30,
            headers={"User-Agent": "FakeSpotter/1.0 rfc3161-verifier"},
        ) as client:

            if params.tsr_hex:
                try:
                    tokens.append(bytes.fromhex(params.tsr_hex.strip()))
                    flags.append("Input: hex-encoded TSR")
                except ValueError as e:
                    return f"[FakeSpotter Error] Invalid hex: {e}"

            elif params.tsr_url:
                resp = await client.get(params.tsr_url)
                resp.raise_for_status()
                tokens.append(resp.content)
                flags.append(f"Input: .tsr file ({len(resp.content)} bytes)")

            elif params.pdf_url:
                resp = await client.get(params.pdf_url)
                resp.raise_for_status()
                pdf_bytes = resp.content
                if pdf_bytes[:4] != b"%PDF":
                    return "[FakeSpotter Error] File is not a PDF"
                tokens = _extract_timestamps_from_pdf(pdf_bytes)
                flags.append(f"Input: PDF ({len(pdf_bytes)} bytes, {len(tokens)} timestamp(s) found)")
            else:
                return "[FakeSpotter Error] Provide pdf_url, tsr_url, or tsr_hex."

        if not tokens:
            verdict = "NO_TIMESTAMP_FOUND"
            trust   = 50
            flags.append("No RFC 3161 timestamp tokens found in the document")
            findings = {
                "verdict": verdict, "trust_score": trust,
                "timestamps_found": 0, "forensic_flags": flags,
            }
        else:
            results = []
            for i, tsr in enumerate(tokens, 1):
                r = _verify_tsr_bytes(tsr)
                results.append(r)
                label = f"Timestamp {i}"
                if r["trusted_time"]:
                    flags.append(f"{label}: trusted time = {r['trusted_time']}")
                if r["tsa_name"]:
                    flags.append(f"{label}: TSA = {r['tsa_name'][:80]}")
                if r["hash_algorithm"]:
                    flags.append(f"{label}: algorithm = {r['hash_algorithm']}")
                if r["error"]:
                    flags.append(f"⚠ {label}: {r['error']}")
                # Document hash verification
                if params.document_hash and r["message_imprint_hex"]:
                    expected = params.document_hash.lower().strip()
                    actual   = r["message_imprint_hex"].lower()
                    if expected == actual:
                        flags.append(f"{label}: document hash MATCHES ✓")
                    else:
                        flags.append(f"⚠ {label}: document hash MISMATCH — token covers different document")

            all_valid = all(r["valid"] for r in results)
            any_error = any(r["error"] for r in results)

            if all_valid and not any_error:
                verdict = "TIMESTAMP_VALID"
                trust   = 100
            elif any_error and "expired" in " ".join(r["error"] for r in results).lower():
                verdict = "TIMESTAMP_EXPIRED"
                trust   = 20
            else:
                verdict = "TIMESTAMP_INVALID"
                trust   = 0

            findings = {
                "verdict":          verdict,
                "trust_score":      trust,
                "timestamps_found": len(tokens),
                "timestamp_results": results,
                "forensic_flags":   flags,
            }

        if params.report_mode == "quick":
            label = (
                i18n.t("verdict_authentic", params.lang) if verdict == "TIMESTAMP_VALID"
                else i18n.t("verdict_fake", params.lang)
                if verdict in ("TIMESTAMP_INVALID", "TIMESTAMP_EXPIRED")
                else i18n.t("verdict_uncertain", params.lang)
            )
            return f"{label} ({trust}/100) — {verdict} | {' | '.join(flags[:3])}"

        report = ForensicReporter.generate_report("verify_rfc3161_timestamp", findings, params.lang)
        return ForensicReporter.format_certificate(report, findings)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_verify_rfc3161_timestamp(mcp)
