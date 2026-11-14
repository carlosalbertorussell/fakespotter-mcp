"""
Gap 1 — Invoice Guard core: check_email_headers + verify_document_integrity,
called through the MCP client API against the real implementation.
"""
from __future__ import annotations

import hashlib

import pytest

from tests.fixtures.email_samples import CLEAN_HEADERS, SPOOFED_HEADERS
from tests.mcp_client import call_tool

# ---------------------------------------------------------------------------
# check_email_headers
# ---------------------------------------------------------------------------


def _headers(raw: str, mode: str = "full"):
    return call_tool("check_email_headers", raw_headers=raw, report_mode=mode)


@pytest.mark.parametrize("raw", CLEAN_HEADERS)
def test_clean_headers_verdict(raw):
    res = _headers(raw)
    assert not res.is_error
    assert res.verdict == "HEADERS_CLEAN", res.text


@pytest.mark.parametrize("raw", SPOOFED_HEADERS)
def test_spoofed_headers_high_risk(raw):
    res = _headers(raw)
    assert not res.is_error
    assert res.verdict == "HIGH_SPOOFING_RISK", res.text


def test_spoofed_headers_flags_name_the_signals():
    res = _headers(SPOOFED_HEADERS[3])
    assert "SPF FAIL" in res.text
    assert "DKIM signature FAIL" in res.text
    assert "DMARC FAIL" in res.text
    assert "Domain mismatch: From='paypal.com' vs Return-Path='paypa1.xyz'" in res.text
    assert "Reply-To hijack: Reply-To domain 'evil.ru'" in res.text


def test_softfail_without_dkim_is_moderate():
    # softfail 20 + no DKIM 15 = 35 -> MODERATE_RISK
    raw = ("Authentication-Results: spf=softfail dkim=none dmarc=pass\n"
           "From: AP <ap@small-co.com>\nReturn-Path: <ap@small-co.com>")
    assert _headers(raw).verdict == "MODERATE_RISK"


def test_bulk_mailer_rule_adds_10():
    # 25 (no DKIM + no DMARC) is clean; +10 for a bulk mailer crosses 35.
    base = CLEAN_HEADERS[2]
    assert _headers(base).verdict == "HEADERS_CLEAN"
    res = _headers(base + "\nX-Mailer: PHPMailer 6.9.1")
    assert res.verdict == "MODERATE_RISK", res.text
    assert "Bulk mailer detected: phpmailer" in res.text


def test_relay_depth_rule_adds_15():
    hops = "".join(f"Received: from relay{i}.example.net by relay{i+1}.example.net\n" for i in range(9))
    res = _headers(hops + CLEAN_HEADERS[2])
    assert res.verdict == "MODERATE_RISK", res.text
    assert "Unusual relay chain depth: 9 hops" in res.text


def test_eight_hops_is_not_flagged():
    hops = "".join(f"Received: from relay{i}.example.net by relay{i+1}.example.net\n" for i in range(8))
    res = _headers(hops + CLEAN_HEADERS[2])
    assert res.verdict == "HEADERS_CLEAN"


def test_quick_mode_clean_headers_reported_authentic():
    res = _headers(CLEAN_HEADERS[0], mode="quick")
    assert "AUTHENTIC" in res.text


def test_quick_mode_spoofed_headers_reported_fake():
    res = _headers(SPOOFED_HEADERS[0], mode="quick")
    assert "FAKE" in res.text


@pytest.mark.parametrize("raw", CLEAN_HEADERS + SPOOFED_HEADERS)
def test_quick_mode_names_the_full_mode_verdict(raw):
    full = _headers(raw)
    quick = _headers(raw, mode="quick")
    assert f"— {full.verdict} |" in quick.text, quick.text


def test_quick_mode_moderate_risk_is_uncertain():
    raw = ("Authentication-Results: spf=softfail dkim=none dmarc=pass\n"
           "From: AP <ap@small-co.com>\nReturn-Path: <ap@small-co.com>")
    res = _headers(raw, mode="quick")
    assert "UNCERTAIN" in res.text and "MODERATE_RISK" in res.text, res.text


# ---------------------------------------------------------------------------
# verify_document_integrity
# ---------------------------------------------------------------------------

INVOICE = b"%PDF-1.4\n% FakeSpotter test invoice\n" + bytes(range(256)) * 8 + b"\n%%EOF\n"
INVOICE_SHA = hashlib.sha256(INVOICE).hexdigest()


def _flip(data: bytes, pos: int) -> bytes:
    b = bytearray(data)
    b[pos] ^= 0x01
    return bytes(b)


def test_document_intact(web):
    url = web.serve("https://files.example.test/invoice.pdf", INVOICE, "application/pdf")
    res = call_tool("verify_document_integrity", file_url=url,
                    expected_sha256=INVOICE_SHA, report_mode="full")
    assert res.verdict == "DOCUMENT_INTACT", res.text
    assert "None detected" in res.text


def test_document_intact_uppercase_hash(web):
    url = web.serve("https://files.example.test/invoice.pdf", INVOICE, "application/pdf")
    res = call_tool("verify_document_integrity", file_url=url,
                    expected_sha256=INVOICE_SHA.upper(), report_mode="full")
    assert res.verdict == "DOCUMENT_INTACT"


@pytest.mark.parametrize("pos", [0, len(INVOICE) // 2, len(INVOICE) - 1])
def test_document_one_byte_flipped_is_tampered(web, pos):
    tampered = _flip(INVOICE, pos)
    url = web.serve("https://files.example.test/invoice.pdf", tampered, "application/pdf")
    res = call_tool("verify_document_integrity", file_url=url,
                    expected_sha256=INVOICE_SHA, report_mode="full")
    assert res.verdict == "DOCUMENT_TAMPERED", res.text
    assert f"Expected: {INVOICE_SHA}" in res.text
    assert f"Computed: {hashlib.sha256(tampered).hexdigest()}" in res.text


def test_document_quick_mode(web):
    url = web.serve("https://files.example.test/invoice.pdf", INVOICE, "application/pdf")
    ok = call_tool("verify_document_integrity", file_url=url, expected_sha256=INVOICE_SHA)
    assert "SHA-256 MATCH" in ok.text and "AUTHENTIC" in ok.text
    web.serve(url, _flip(INVOICE, 10), "application/pdf")
    bad = call_tool("verify_document_integrity", file_url=url, expected_sha256=INVOICE_SHA)
    assert "SHA-256 MISMATCH" in bad.text and "FAKE" in bad.text


def test_document_rejects_malformed_hash():
    res = call_tool("verify_document_integrity", file_url="https://files.example.test/x",
                    expected_sha256="not-a-hash")
    assert res.is_error


def test_document_download_failure_is_reported(web):
    res = call_tool("verify_document_integrity", file_url="https://files.example.test/missing.pdf",
                    expected_sha256=INVOICE_SHA)
    assert res.text.startswith("[FakeSpotter Error]")


# ---------------------------------------------------------------------------
# analyze_url_reputation (Invoice Guard step 3) — offline: DNS is patched,
# HTTP is served by the fixture. Added because moving eval_deterministic.py
# onto the real tool exposed the bug below.
# ---------------------------------------------------------------------------

_SECURE_HEADERS = {
    "strict-transport-security": "max-age=63072000",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
}


def test_url_reputation_good_domain(web):
    import socket
    from unittest.mock import patch

    web.serve("https://supplier.example.com", b"<html>ok</html>", "text/html", _SECURE_HEADERS)
    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))]
    with patch("socket.getaddrinfo", return_value=fake_dns):
        res = call_tool("analyze_url_reputation", url="supplier.example.com", report_mode="full")
    assert res.verdict == "GOOD_REPUTATION", res.text


def test_url_reputation_unresolvable_domain_is_not_good(web):
    import socket
    from unittest.mock import patch

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        res = call_tool("analyze_url_reputation", url="no-such-supplier.invalid", report_mode="full")
    assert res.verdict in ("POOR_REPUTATION", "MODERATE_RISK"), res.text


def test_url_reputation_unresolvable_domain_flags(web):
    import socket
    from unittest.mock import patch

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        res = call_tool("analyze_url_reputation", url="no-such-supplier.invalid", report_mode="full")
    assert "Domain does not resolve: no-such-supplier.invalid" in res.text
    assert "Cannot connect" in res.text
    assert "AttributeError" not in res.text


def _resolves():
    import socket
    from unittest.mock import patch

    fake_dns = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 0))]
    return patch("socket.getaddrinfo", return_value=fake_dns)


def test_url_reputation_tls_error_scores_20(web):
    import ssl

    import httpx

    def handler(request):
        try:
            raise ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] self-signed")
        except ssl.SSLError as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc

    web.handler = handler
    with _resolves():
        res = call_tool("analyze_url_reputation", url="selfsigned.example.com")
    # Resolves, TLS fails: the intended +20 risk points -> trust 80.
    assert "(80/100) — " in res.text, res.text
    assert "TLS/SSL certificate error — invalid or self-signed" in res.text


def test_url_reputation_quick_mode_good_domain(web):
    web.serve("https://supplier.example.com", b"<html>ok</html>", "text/html", _SECURE_HEADERS)
    with _resolves():
        res = call_tool("analyze_url_reputation", url="supplier.example.com")
    assert "AUTHENTIC" in res.text and "GOOD_REPUTATION" in res.text, res.text
