"""
FakeSpotter — tools/signature_tools.py
Digital Signature Verifier (tool #21)

Verifies PKCS#7/CMS digital signatures embedded in PDF documents
(Adobe Acrobat, DocuSign, qualified electronic signatures).

Checks:
  - Signer identity (CN, Organisation, Country from X.509 certificate)
  - Certificate validity period
  - Certificate chain of trust
  - Document integrity: was the document modified after signing?
  - Signature coverage: does the signature cover the entire document?
  - Number and order of signatures

Dependencies:
  pyhanko>=0.20,<1
  cryptography>=42,<44
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Signature extraction helpers
# ---------------------------------------------------------------------------

def _name_attr(name, key: str) -> str:
    """One attribute of an asn1crypto x509.Name (``.native`` is a dict of str/list)."""
    value = (name.native or {}).get(key, "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value)


async def _verify_signatures(pdf_bytes: bytes) -> list[dict]:
    """
    Extract and verify all digital signatures in a PDF.
    Returns list of per-signature result dicts.

    Uses pyHanko's async validation API: the synchronous wrappers call
    ``asyncio.run`` and cannot be used from inside the running event loop.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.ades.report import AdESIndeterminate
    from pyhanko.sign.validation import SignatureCoverageLevel, async_validate_pdf_signature
    from pyhanko_certvalidator.context import ValidationContext
    import io

    # Trust problems that mean "the chain validates, but the certificate's
    # validity period has ended" (pyHanko reports an expired end-entity
    # certificate without proof of existence as OUT_OF_BOUNDS_NO_POE).
    expiry_only = {
        AdESIndeterminate.OUT_OF_BOUNDS_NO_POE,
        AdESIndeterminate.OUT_OF_BOUNDS_NOT_REVOKED,
        AdESIndeterminate.EXPIRED,
    }

    results = []
    reader = PdfFileReader(io.BytesIO(pdf_bytes))
    sig_fields = reader.embedded_signatures

    for i, sig in enumerate(sig_fields):
        result: dict = {
            "index":       i + 1,
            "field_name":  sig.field_name or f"Signature{i+1}",
            "signer_cn":   "",
            "signer_org":  "",
            "signer_country": "",
            "valid_from":  "",
            "valid_until": "",
            "cert_expired": False,
            "cert_chain_ok": False,
            "integrity_ok": False,
            "covers_whole_doc": False,
            "signing_time": "",
            "error": "",
        }

        try:
            # Signer info from certificate (asn1crypto x509.Certificate)
            cert = sig.signer_cert
            if cert is not None:
                subject = cert.subject
                result["signer_cn"]      = _name_attr(subject, "common_name")
                result["signer_org"]     = _name_attr(subject, "organization_name")
                result["signer_country"] = _name_attr(subject, "country_name")
                not_before = cert.not_valid_before
                not_after  = cert.not_valid_after
                result["valid_from"]  = not_before.isoformat()
                result["valid_until"] = not_after.isoformat()
                if not_after.tzinfo is None:
                    not_after = not_after.replace(tzinfo=timezone.utc)
                result["cert_expired"] = not_after < datetime.now(timezone.utc)

            # Validate signature (integrity + cert chain)
            vc = ValidationContext(allow_fetching=True)
            status = await async_validate_pdf_signature(sig, vc)

            result["integrity_ok"]  = bool(status.intact)
            result["cert_chain_ok"] = bool(status.trusted) or (
                # The chain itself is fine; only the validity period has ended.
                # Reported through cert_expired instead of as a broken chain.
                result["cert_expired"]
                and status.intact and status.valid
                and status.trust_problem_indic in expiry_only
            )
            result["covers_whole_doc"] = status.coverage in (
                SignatureCoverageLevel.ENTIRE_FILE,
                SignatureCoverageLevel.ENTIRE_REVISION,
            )

            # Signing time
            if status.signer_reported_dt:
                result["signing_time"] = status.signer_reported_dt.isoformat()

        except Exception as exc:
            result["error"] = str(exc)[:200]

        results.append(result)

    return results


def _aggregate_verdict(sig_results: list[dict]) -> tuple[str, int, list[str]]:
    """Aggregate per-signature results into a single verdict."""
    flags: list[str] = []

    if not sig_results:
        return "NO_SIGNATURE_FOUND", 0, ["No digital signatures embedded in this PDF"]

    issues = 0
    for r in sig_results:
        label = f"Signature {r['index']} ({r['field_name']})"

        if r["error"]:
            flags.append(f"{label}: validation error — {r['error']}")
            issues += 2
            continue

        if not r["integrity_ok"]:
            flags.append(f"{label}: DOCUMENT MODIFIED AFTER SIGNING")
            issues += 3
        if r["cert_expired"]:
            flags.append(f"{label}: certificate EXPIRED (until {r['valid_until']})")
            issues += 2
        if not r["cert_chain_ok"]:
            flags.append(f"{label}: certificate chain INVALID")
            issues += 2
        if not r["covers_whole_doc"]:
            flags.append(f"{label}: signature does NOT cover the whole document")
            issues += 1
        if r["integrity_ok"] and r["cert_chain_ok"] and not r["cert_expired"]:
            signer = r["signer_cn"] or "Unknown"
            flags.append(f"{label}: VALID — signed by {signer} ({r['signer_country']})")

    if issues == 0:
        verdict = "SIGNATURE_VALID"
        trust   = 100
    elif any("MODIFIED AFTER SIGNING" in f for f in flags):
        verdict = "DOCUMENT_MODIFIED_AFTER_SIGNING"
        trust   = 0
    elif any("EXPIRED" in f for f in flags) and issues < 4:
        verdict = "SIGNATURE_EXPIRED"
        trust   = 20
    else:
        verdict = "SIGNATURE_INVALID"
        trust   = 0

    return verdict, trust, flags


# ---------------------------------------------------------------------------
# Tool: verify_digital_signature
# ---------------------------------------------------------------------------

class VerifyDigitalSignatureInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    file_url:    str = Field(
        ...,
        description=(
            "Public URL of a digitally signed PDF. "
            "Supports PKCS#7/CMS signatures (Adobe Acrobat, DocuSign, "
            "qualified electronic signatures / eIDAS)."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_digital_signature(mcp: MCPServer) -> None:

    @mcp.tool(
        name="verify_digital_signature",
        annotations={
            "title": "Digital Signature Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_digital_signature(params: VerifyDigitalSignatureInput) -> str:
        """
        Verifies PKCS#7/CMS digital signatures embedded in PDF documents.

        Checks performed per signature:
          - Signer identity (CN, Organisation, Country from X.509 certificate)
          - Certificate validity period (not expired)
          - Certificate chain of trust (trusted root)
          - Document integrity: no modifications after signing
          - Signature coverage: full document vs. partial

        Verdicts:
          SIGNATURE_VALID               — all signatures intact and trusted
          SIGNATURE_INVALID             — certificate chain or trust failure
          SIGNATURE_EXPIRED             — certificate was valid but has expired
          DOCUMENT_MODIFIED_AFTER_SIGNING — content changed post-signature
          NO_SIGNATURE_FOUND            — no embedded digital signatures

        Args:
            params.file_url:    URL of a signed PDF
            params.lang:        en | es
            params.report_mode: quick | full
        """
        try:
            # Download
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 signature-verifier"},
            ) as client:
                resp = await client.get(params.file_url)
                resp.raise_for_status()
                pdf_bytes = resp.content

            if pdf_bytes[:4] != b"%PDF":
                return "[FakeSpotter Error] File does not appear to be a PDF (magic bytes check failed)"

            # Verify
            try:
                sig_results = await _verify_signatures(pdf_bytes)
            except ImportError:
                return (
                    "[FakeSpotter Error] pyhanko not installed. "
                    "Add pyhanko>=0.20,<1 and cryptography>=42,<44 to requirements.txt."
                )

            verdict, trust, flags = _aggregate_verdict(sig_results)

            findings = {
                "verdict":           verdict,
                "trust_score":       trust,
                "signatures_found":  len(sig_results),
                "signatures":        sig_results,
                "file_sha256":       hashlib.sha256(pdf_bytes).hexdigest(),
                "file_size_bytes":   len(pdf_bytes),
                "forensic_flags":    flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "SIGNATURE_VALID"
                    else i18n.t("verdict_fake", params.lang)
                    if verdict in ("SIGNATURE_INVALID", "DOCUMENT_MODIFIED_AFTER_SIGNING")
                    else i18n.t("verdict_uncertain", params.lang)
                )
                flag_str = " | ".join(flags[:3])
                return f"{label} ({trust}/100) — {verdict} | {flag_str}"

            report = ForensicReporter.generate_report("verify_digital_signature", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: MCPServer) -> None:
    register_verify_digital_signature(mcp)
