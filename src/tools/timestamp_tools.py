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
  TIMESTAMP_INVALID   — token tampered, TSA signature/chain invalid, or the
                        token does not cover the given document_hash
  TIMESTAMP_EXPIRED   — token intact and chain valid, but the TSA certificate
                        has expired (the flags say whether before or after
                        the stamping time)
  NO_TIMESTAMP_FOUND  — no embedded timestamp in the document

Dependency: pyhanko (already in requirements from S12)
"""
from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from typing import Literal

import httpx
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Timestamp extraction and verification
# ---------------------------------------------------------------------------

def _empty_result(source: str) -> dict:
    return {
        "source":         source,
        "valid":          False,
        "intact":         False,
        "expired":        False,
        "trusted_time":   None,
        "tsa_name":       "",
        "tsa_cert_valid_until": "",
        "hash_algorithm": "",
        "message_imprint_hex": "",
        "policy_oid":     "",
        "serial_number":  "",
        "error":          "",
    }


def _tsa_signing_cert(signed_data):
    """The certificate matching the token's SignerInfo sid (falls back to the first one)."""
    certs = [c.chosen for c in (signed_data["certificates"] or []) if c.name == "certificate"]
    if not certs:
        return None
    try:
        sid = signed_data["signer_infos"][0]["sid"]
        if sid.name == "issuer_and_serial_number":
            want = sid.chosen
            for cert in certs:
                if (cert.issuer == want["issuer"]
                        and cert.serial_number == want["serial_number"].native):
                    return cert
        elif sid.name == "subject_key_identifier":
            for cert in certs:
                if cert.key_identifier == sid.chosen.native:
                    return cert
    except Exception:
        pass
    return certs[0]


async def _verify_tst(signed_data, source: str, expected_imprint=None) -> dict:
    """
    Verify the SignedData of an RFC 3161 TimeStampToken with pyHanko.

    ``expected_imprint`` is a callable (hash algorithm name -> digest) giving
    the message imprint the token must cover, e.g. the digest of the PDF
    signature it timestamps. Without one (a standalone .tsr), the token's own
    imprint is used, so only the token's signature and chain are checked;
    the caller compares the imprint against ``document_hash`` separately.
    """
    from pyhanko.sign.ades.report import AdESIndeterminate
    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
    from pyhanko_certvalidator.context import ValidationContext

    result = _empty_result(source)

    try:
        tst_info = signed_data["encap_content_info"]["content"].parsed
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
        token_imprint = msg_imprint["hashed_message"].native
        result["message_imprint_hex"] = token_imprint.hex()

        # TSA identity (the certificate that signed the token)
        tsa_cert = _tsa_signing_cert(signed_data)
        if tsa_cert is not None:
            result["tsa_name"] = tsa_cert.subject.human_friendly
            result["tsa_cert_valid_until"] = tsa_cert.not_valid_after.isoformat()

        # Validate signature, imprint and TSA chain of trust
        vc = ValidationContext(allow_fetching=True)
        status = await validate_tst_signed_data(
            signed_data, vc, expected_imprint or (lambda _algo: token_imprint),
        )
        intact = bool(status.get("intact"))
        valid  = bool(status.get("valid"))
        problem = status.get("trust_problem_indic")
        trusted = intact and valid and problem is None and status.get("validation_path") is not None
        result["intact"] = intact
        result["valid"]  = trusted

        if not intact:
            result["error"] = "Timestamp token integrity check failed — token may be tampered"
        elif not valid:
            result["error"] = "Timestamp token signature is invalid"
        elif not trusted:
            not_after = tsa_cert.not_valid_after if tsa_cert is not None else None
            if (
                problem in (AdESIndeterminate.OUT_OF_BOUNDS_NO_POE,
                            AdESIndeterminate.OUT_OF_BOUNDS_NOT_REVOKED,
                            AdESIndeterminate.EXPIRED)
                and not_after is not None
                and not_after < datetime.now(timezone.utc)
            ):
                result["expired"] = True
                when = (
                    "before the stamping time" if isinstance(gen_time, datetime) and not_after < gen_time
                    else "after the stamping time; no long-term validation data proves it was valid then"
                )
                result["error"] = f"TSA certificate expired on {not_after.isoformat()} ({when})"
            else:
                reason = getattr(problem, "name", None) or "no trusted path"
                result["error"] = f"TSA certificate chain validation failed ({reason})"

    except Exception as exc:
        result["error"] = str(exc)[:300] or type(exc).__name__

    return result


async def _verify_tsr_bytes(tsr_bytes: bytes) -> dict:
    """
    Verify an RFC 3161 TimeStampResp (.tsr) using pyhanko.
    Returns a dict with validity, time, TSA info, and any errors.
    """
    from asn1crypto import core, tsp

    def _fail(message: str) -> dict:
        result = _empty_result("tsr")
        result["error"] = message
        return result

    try:
        # Read PKIStatusInfo on its own first: a rejection carries no token,
        # and asn1crypto refuses to parse a TimeStampResp without one.
        status_info = tsp.PKIStatusInfo.load(core.Sequence.load(tsr_bytes)[0].dump())
        status = status_info["status"].native
    except Exception as exc:
        detail = " ".join((str(exc) or type(exc).__name__).split())[:200]
        return _fail(f"Not a valid RFC 3161 TimeStampResp: {detail}")
    if status not in ("granted", "granted_with_mods"):
        return _fail(f"TSA returned status: {status}")

    try:
        signed_data = tsp.TimeStampResp.load(tsr_bytes)["time_stamp_token"]["content"]
    except Exception as exc:
        detail = " ".join((str(exc) or type(exc).__name__).split())[:200]
        return _fail(f"Not a valid RFC 3161 TimeStampResp: {detail}")

    return await _verify_tst(signed_data, "tsr")


def _extract_timestamps_from_pdf(pdf_bytes: bytes) -> list[tuple[str, object, object]]:
    """
    Extract RFC 3161 timestamp tokens embedded in a PDF.

    Returns ``(source, SignedData, expected_imprint)`` tuples for:
      - signature timestamps (unsigned attribute signatureTimeStampToken),
        which must cover the digest of the signature value;
      - content timestamps (signed attribute content-time-stamp), which must
        cover the signed byte range;
      - document timestamps (/DocTimeStamp, ETSI.RFC3161), whose SignedData
        is itself the token and must cover the signed byte range.
    """
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.general import find_cms_attribute_iter
    from pyhanko.sign.validation.generic_cms import message_imprint_checker

    found: list[tuple[str, object, object]] = []
    doc = PdfFileReader(io.BytesIO(pdf_bytes))

    for sig in doc.embedded_signatures:
        name = sig.field_name or "signature"
        try:
            if sig.sig_object_type == "/DocTimeStamp":
                found.append((f"document timestamp '{name}'", sig.signed_data, sig.compute_digest))
                continue
            signer_info = sig.signer_info
            for token in find_cms_attribute_iter(signer_info["unsigned_attrs"],
                                                 "signature_time_stamp_token"):
                found.append((f"signature timestamp of '{name}'", token["content"],
                              message_imprint_checker(signer_info)))
            for token in find_cms_attribute_iter(signer_info["signed_attrs"],
                                                 "content_time_stamp"):
                found.append((f"content timestamp of '{name}'", token["content"],
                              sig.compute_digest))
        except Exception:
            # Malformed or absent attributes: nothing to extract for this field.
            pass

    return found


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


def register_verify_rfc3161_timestamp(mcp: MCPServer) -> None:

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
          TIMESTAMP_INVALID   — tampered token, invalid TSA chain, or token
                                does not cover document_hash
          TIMESTAMP_EXPIRED   — TSA certificate has expired (at or after
                                stamping time; see flags)
          NO_TIMESTAMP_FOUND  — no embedded timestamp in the document

        Requires: pyhanko (already in requirements from S12)
        """
        try:
            import pyhanko  # noqa — trigger ImportError if missing
        except ImportError:
            return "[FakeSpotter Error] pyhanko not installed. Add pyhanko>=0.37.0,<1 to requirements.txt."

        flags:  list[str] = []
        tsr_inputs: list[bytes] = []
        pdf_tokens: list[tuple[str, object, object]] = []

        async with httpx.AsyncClient(
            follow_redirects=True, timeout=30,
            headers={"User-Agent": "FakeSpotter/1.0 rfc3161-verifier"},
        ) as client:

            if params.tsr_hex:
                try:
                    tsr_inputs.append(bytes.fromhex(params.tsr_hex.strip()))
                    flags.append("Input: hex-encoded TSR")
                except ValueError as e:
                    return f"[FakeSpotter Error] Invalid hex: {e}"

            elif params.tsr_url:
                resp = await client.get(params.tsr_url)
                resp.raise_for_status()
                tsr_inputs.append(resp.content)
                flags.append(f"Input: .tsr file ({len(resp.content)} bytes)")

            elif params.pdf_url:
                resp = await client.get(params.pdf_url)
                resp.raise_for_status()
                pdf_bytes = resp.content
                if pdf_bytes[:4] != b"%PDF":
                    return "[FakeSpotter Error] File is not a PDF"
                pdf_tokens = _extract_timestamps_from_pdf(pdf_bytes)
                flags.append(f"Input: PDF ({len(pdf_bytes)} bytes, {len(pdf_tokens)} timestamp(s) found)")
            else:
                return "[FakeSpotter Error] Provide pdf_url, tsr_url, or tsr_hex."

        token_count = len(tsr_inputs) + len(pdf_tokens)
        if not token_count:
            verdict = "NO_TIMESTAMP_FOUND"
            trust   = 50
            flags.append("No RFC 3161 timestamp tokens found in the document")
            findings = {
                "verdict": verdict, "trust_score": trust,
                "timestamps_found": 0, "forensic_flags": flags,
            }
        else:
            results = [await _verify_tsr_bytes(tsr) for tsr in tsr_inputs]
            for source, signed_data, imprint in pdf_tokens:
                results.append(await _verify_tst(signed_data, source, imprint))

            hash_mismatch = False
            for i, r in enumerate(results, 1):
                label = f"Timestamp {i}"
                if r["source"] != "tsr":
                    flags.append(f"{label}: {r['source']}")
                if r["trusted_time"]:
                    flags.append(f"{label}: trusted time = {r['trusted_time']}")
                if r["tsa_name"]:
                    flags.append(f"{label}: TSA = {r['tsa_name'][:80]}")
                if r["hash_algorithm"]:
                    flags.append(f"{label}: algorithm = {r['hash_algorithm']}")
                if r["error"]:
                    flags.append(f"⚠ {label}: {r['error']}")
                # Document hash verification (document_hash is SHA-256)
                if params.document_hash and r["message_imprint_hex"]:
                    expected = params.document_hash.lower().strip()
                    actual   = r["message_imprint_hex"].lower()
                    if r["hash_algorithm"] != "sha256":
                        flags.append(
                            f"⚠ {label}: token imprint uses {r['hash_algorithm']}, "
                            "cannot compare with the SHA-256 document_hash")
                    elif expected == actual:
                        flags.append(f"{label}: document hash MATCHES ✓")
                    else:
                        hash_mismatch = True
                        flags.append(f"⚠ {label}: document hash MISMATCH — token covers different document")

            if all(r["valid"] for r in results) and not hash_mismatch:
                verdict = "TIMESTAMP_VALID"
                trust   = 100
            elif not hash_mismatch and all(r["valid"] or r["expired"] for r in results):
                verdict = "TIMESTAMP_EXPIRED"
                trust   = 20
            else:
                verdict = "TIMESTAMP_INVALID"
                trust   = 0

            findings = {
                "verdict":          verdict,
                "trust_score":      trust,
                "timestamps_found": token_count,
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

def register_all(mcp: MCPServer) -> None:
    register_verify_rfc3161_timestamp(mcp)
