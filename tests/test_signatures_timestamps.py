"""
Gap 3 — verify_digital_signature and verify_rfc3161_timestamp (pyHanko),
with a throw-away PKI, real PAdES signatures and a local offline TSA built
at test time (tests/pki.py).

The tools build ``ValidationContext(allow_fetching=True)`` with no way to
pass trust roots, so a test certificate can never be trusted. The
``trust_test_root`` fixture patches pyhanko_certvalidator's ValidationContext
to add the test root and disable fetching; validation itself is untouched.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
from unittest.mock import patch

import pytest
from asn1crypto import tsp

from tests import pki
from tests.mcp_client import call_tool

PDF_URL = "https://files.example.test/contract.pdf"
TSR_URL = "https://files.example.test/contract.tsr"


@pytest.fixture
def trust_test_root():
    import pyhanko_certvalidator.context as ctx

    real = ctx.ValidationContext
    root = pki.test_pki().root.cert

    def _context(*args, **kwargs):
        kwargs.setdefault("trust_roots", [root])
        kwargs["allow_fetching"] = False
        return real(*args, **kwargs)

    with patch.object(ctx, "ValidationContext", _context):
        yield


@pytest.fixture(scope="module")
def unsigned_pdf() -> bytes:
    return pki.make_pdf()


@pytest.fixture(scope="module")
def signed_pdf(unsigned_pdf) -> bytes:
    return pki.sign_pdf(unsigned_pdf)


@pytest.fixture(scope="module")
def signed_pdf_with_tst(unsigned_pdf) -> bytes:
    return pki.sign_pdf(unsigned_pdf, with_timestamp=True)


# ---------------------------------------------------------------------------
# Fixture sanity: pyHanko itself, with the test root trusted, accepts the
# signature and the token. Expected failures below are therefore the tool's.
# ---------------------------------------------------------------------------

def _vc():
    from pyhanko_certvalidator import ValidationContext

    return ValidationContext(trust_roots=[pki.test_pki().root.cert], allow_fetching=False)


def _imprint(document: bytes):
    return lambda algo: hashlib.new(algo, document).digest()


def test_fixture_signature_is_valid_per_pyhanko(signed_pdf):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    sig = PdfFileReader(io.BytesIO(signed_pdf)).embedded_signatures[0]
    status = validate_pdf_signature(sig, _vc())
    assert status.intact and status.valid and status.bottom_line


def test_fixture_signature_timestamp_is_embedded_per_pyhanko(signed_pdf_with_tst):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    sig = PdfFileReader(io.BytesIO(signed_pdf_with_tst)).embedded_signatures[0]
    status = validate_pdf_signature(sig, _vc(), ts_validation_context=_vc())
    assert status.timestamp_validity is not None
    assert status.timestamp_validity.intact and status.timestamp_validity.valid


def test_fixture_tampered_signature_is_broken_per_pyhanko(signed_pdf):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature

    tampered = pki.tamper_signed_content(signed_pdf)
    sig = PdfFileReader(io.BytesIO(tampered)).embedded_signatures[0]
    assert not validate_pdf_signature(sig, _vc()).intact


def test_fixture_tsr_is_valid_per_pyhanko(unsigned_pdf):
    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data

    resp = tsp.TimeStampResp.load(pki.make_tsr(unsigned_pdf))
    assert resp["status"]["status"].native == "granted"
    status = asyncio.run(validate_tst_signed_data(
        resp["time_stamp_token"]["content"], _vc(), _imprint(unsigned_pdf)))
    assert status["intact"] and status["valid"]


# ---------------------------------------------------------------------------
# verify_digital_signature
# ---------------------------------------------------------------------------

def _sig(web, body: bytes):
    web.serve(PDF_URL, body, "application/pdf")
    return call_tool("verify_digital_signature", file_url=PDF_URL, report_mode="full")


def test_unsigned_pdf_has_no_signature(web, unsigned_pdf):
    res = _sig(web, unsigned_pdf)
    assert res.verdict == "NO_SIGNATURE_FOUND", res.text
    assert "No digital signatures embedded in this PDF" in res.text


def test_signature_rejects_non_pdf(web):
    web.serve(PDF_URL, b"PK\x03\x04 not a pdf", "application/pdf")
    res = call_tool("verify_digital_signature", file_url=PDF_URL)
    assert res.text == "[FakeSpotter Error] File does not appear to be a PDF (magic bytes check failed)"


def test_valid_signature(web, signed_pdf, trust_test_root):
    res = _sig(web, signed_pdf)
    assert res.verdict == "SIGNATURE_VALID", res.text
    assert "VALID — signed by Test Supplier SA (AR)" in res.text


def test_modified_after_signing(web, signed_pdf, trust_test_root):
    res = _sig(web, pki.tamper_signed_content(signed_pdf))
    assert res.verdict == "DOCUMENT_MODIFIED_AFTER_SIGNING", res.text
    assert "DOCUMENT MODIFIED AFTER SIGNING" in res.text


def test_modified_after_signing_is_never_valid(web, signed_pdf, trust_test_root):
    res = _sig(web, pki.tamper_signed_content(signed_pdf))
    assert res.verdict in ("DOCUMENT_MODIFIED_AFTER_SIGNING", "SIGNATURE_INVALID"), res.text


def test_untrusted_signer_is_invalid(web, signed_pdf):
    # No trust patch: the test root is unknown, so the chain cannot validate.
    res = _sig(web, signed_pdf)
    assert res.verdict == "SIGNATURE_INVALID", res.text


def test_untrusted_signer_flags_chain(web, signed_pdf):
    res = _sig(web, signed_pdf)
    assert "certificate chain INVALID" in res.text, res.text


@pytest.fixture(scope="module")
def expired_signed_pdf(unsigned_pdf) -> bytes:
    return pki.sign_pdf(unsigned_pdf, identity=pki.expired_signer())


def test_fixture_expired_signer_per_pyhanko(expired_signed_pdf):
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.ades.report import AdESIndeterminate
    from pyhanko.sign.validation import validate_pdf_signature

    sig = PdfFileReader(io.BytesIO(expired_signed_pdf)).embedded_signatures[0]
    status = validate_pdf_signature(sig, _vc())
    assert status.intact and status.valid and not status.trusted
    assert status.trust_problem_indic == AdESIndeterminate.OUT_OF_BOUNDS_NO_POE


def test_expired_signer_certificate(web, expired_signed_pdf, trust_test_root):
    res = _sig(web, expired_signed_pdf)
    assert res.verdict == "SIGNATURE_EXPIRED", res.text
    assert "certificate EXPIRED" in res.text
    assert "certificate chain INVALID" not in res.text
    assert "DOCUMENT MODIFIED AFTER SIGNING" not in res.text


def test_expired_signer_quick_mode_is_not_authentic(web, expired_signed_pdf, trust_test_root):
    web.serve(PDF_URL, expired_signed_pdf, "application/pdf")
    res = call_tool("verify_digital_signature", file_url=PDF_URL)
    assert "SIGNATURE_EXPIRED" in res.text, res.text
    assert "AUTHENTIC" not in res.text.split("—")[0].upper(), res.text


def test_expired_and_untrusted_signer_is_invalid(web, expired_signed_pdf):
    # No trust patch: the chain cannot be built, so expiry alone does not explain it.
    res = _sig(web, expired_signed_pdf)
    assert res.verdict == "SIGNATURE_INVALID", res.text
    assert "certificate chain INVALID" in res.text


# ---------------------------------------------------------------------------
# verify_rfc3161_timestamp
# ---------------------------------------------------------------------------

def test_no_timestamp_in_unsigned_pdf(web, unsigned_pdf):
    web.serve(PDF_URL, unsigned_pdf, "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL, report_mode="full")
    assert res.verdict == "NO_TIMESTAMP_FOUND", res.text
    assert "No RFC 3161 timestamp tokens found in the document" in res.text


def test_no_timestamp_in_signed_pdf_without_tst(web, signed_pdf):
    web.serve(PDF_URL, signed_pdf, "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL, report_mode="full")
    assert res.verdict == "NO_TIMESTAMP_FOUND", res.text


def test_signature_timestamp_in_pdf_is_found(web, signed_pdf_with_tst):
    web.serve(PDF_URL, signed_pdf_with_tst, "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL, report_mode="full")
    assert res.verdict != "NO_TIMESTAMP_FOUND", res.text


def test_signature_timestamp_in_pdf_is_valid(web, signed_pdf_with_tst, trust_test_root):
    web.serve(PDF_URL, signed_pdf_with_tst, "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL, report_mode="full")
    assert res.verdict == "TIMESTAMP_VALID", res.text
    assert "1 timestamp(s) found" in res.text
    assert "signature timestamp of 'Signature1'" in res.text
    assert "FakeSpotter Test TSA" in res.text


def test_signature_timestamp_in_pdf_untrusted_tsa(web, signed_pdf_with_tst):
    # No trust patch: the TSA chain cannot validate.
    web.serve(PDF_URL, signed_pdf_with_tst, "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL, report_mode="full")
    assert res.verdict == "TIMESTAMP_INVALID", res.text
    assert "TSA certificate chain validation failed" in res.text


def test_timestamp_rejects_non_pdf(web):
    web.serve(PDF_URL, b"not a pdf", "application/pdf")
    res = call_tool("verify_rfc3161_timestamp", pdf_url=PDF_URL)
    assert res.text == "[FakeSpotter Error] File is not a PDF"


def test_timestamp_invalid_hex():
    res = call_tool("verify_rfc3161_timestamp", tsr_hex="zz-not-hex")
    assert res.text.startswith("[FakeSpotter Error] Invalid hex")


def test_timestamp_requires_input():
    res = call_tool("verify_rfc3161_timestamp")
    assert res.text == "[FakeSpotter Error] Provide pdf_url, tsr_url, or tsr_hex."


def test_valid_tsr_hex(unsigned_pdf, trust_test_root):
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=pki.make_tsr(unsigned_pdf).hex(),
                    report_mode="full")
    assert res.verdict == "TIMESTAMP_VALID", res.text
    assert "TSA = " in res.text and "FakeSpotter Test TSA" in res.text


def test_valid_tsr_url_matches_document_hash(web, unsigned_pdf, trust_test_root):
    web.serve(TSR_URL, pki.make_tsr(unsigned_pdf), "application/timestamp-reply")
    res = call_tool("verify_rfc3161_timestamp", tsr_url=TSR_URL,
                    document_hash=hashlib.sha256(unsigned_pdf).hexdigest(), report_mode="full")
    assert res.verdict == "TIMESTAMP_VALID", res.text
    assert "document hash MATCHES" in res.text


def test_tsr_for_other_document_hash_mismatch(unsigned_pdf, trust_test_root):
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=pki.make_tsr(b"other").hex(),
                    document_hash=hashlib.sha256(unsigned_pdf).hexdigest(), report_mode="full")
    assert "document hash MISMATCH" in res.text, res.text
    # A genuine token for some other document does not vouch for this one.
    assert res.verdict == "TIMESTAMP_INVALID", res.text


def test_untrusted_tsa_is_invalid(unsigned_pdf):
    # No trust patch: the test root is unknown, so the TSA chain cannot validate.
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=pki.make_tsr(unsigned_pdf).hex(),
                    report_mode="full")
    assert res.verdict == "TIMESTAMP_INVALID", res.text
    assert "TSA certificate chain validation failed" in res.text


def test_tsa_expired_before_stamping(unsigned_pdf, trust_test_root):
    tsr = pki.make_tsr(unsigned_pdf, tsa=pki.expired_tsa())
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=tsr.hex(), report_mode="full")
    assert res.verdict == "TIMESTAMP_EXPIRED", res.text
    assert "TSA certificate expired on" in res.text
    assert "before the stamping time" in res.text


def test_tsa_expired_after_stamping(unsigned_pdf, trust_test_root):
    import datetime as dt

    stamped = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)
    tsr = pki.make_tsr(unsigned_pdf, tsa=pki.expired_tsa(), fixed_dt=stamped)
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=tsr.hex(), report_mode="full")
    assert res.verdict == "TIMESTAMP_EXPIRED", res.text
    assert "after the stamping time" in res.text


def test_expired_and_tampered_tsr_is_invalid(unsigned_pdf, trust_test_root):
    raw = pki.make_tsr(unsigned_pdf, tsa=pki.expired_tsa())
    tst_info = tsp.TimeStampResp.load(raw)["time_stamp_token"]["content"][
        "encap_content_info"]["content"].parsed
    serial = tst_info["serial_number"].dump()
    forged = raw.replace(serial, serial[:-1] + bytes([serial[-1] ^ 0x01]))
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=forged.hex(), report_mode="full")
    assert res.verdict == "TIMESTAMP_INVALID", res.text


def _tampered_tsr(document: bytes) -> bytes:
    """Change the serial number inside the signed TSTInfo, keeping the CMS signature."""
    raw = pki.make_tsr(document)
    resp = tsp.TimeStampResp.load(raw)
    tst_info = resp["time_stamp_token"]["content"]["encap_content_info"]["content"].parsed
    serial = tst_info["serial_number"].dump()
    assert raw.count(serial) == 1
    forged = serial[:-1] + bytes([serial[-1] ^ 0x01])
    return raw.replace(serial, forged)


def _rejected_tsr() -> bytes:
    # TimeStampResp ::= SEQUENCE { status PKIStatusInfo { status rejection(2) } } with no token.
    # Hand-encoded: asn1crypto refuses to build one without time_stamp_token.
    return bytes.fromhex("3005300302010" "2")


@pytest.mark.parametrize("make", [
    pytest.param(lambda doc: _tampered_tsr(doc), id="tampered_tstinfo"),
    pytest.param(lambda doc: _rejected_tsr(), id="tsa_rejection"),
    pytest.param(lambda doc: b"\x30\x03\x02\x01\x00", id="garbage_der"),
])
def test_invalid_tsr(unsigned_pdf, trust_test_root, make):
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=make(unsigned_pdf).hex(),
                    report_mode="full")
    assert res.verdict == "TIMESTAMP_INVALID", res.text


def test_tampered_fixture_breaks_signature_per_pyhanko(unsigned_pdf):
    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data

    resp = tsp.TimeStampResp.load(_tampered_tsr(unsigned_pdf))
    status = asyncio.run(validate_tst_signed_data(
        resp["time_stamp_token"]["content"], _vc(), _imprint(unsigned_pdf)))
    assert not status["intact"]


def test_tsa_rejection_reports_status():
    res = call_tool("verify_rfc3161_timestamp", tsr_hex=_rejected_tsr().hex(), report_mode="full")
    assert res.verdict == "TIMESTAMP_INVALID", res.text
    assert "TSA returned status: rejection" in res.text
