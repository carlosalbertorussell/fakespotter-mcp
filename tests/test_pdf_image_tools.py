"""
Gap 4 — tools built on PyMuPDF, Pillow, OpenCV and imagehash:
analyze_pdf_metadata, inspect_qr_code, correlate_documents.

Fixtures are rendered at test time with the real libraries (tests/images.py),
so these are the tests that should catch the pymupdf 2 / pillow 13 upgrades.
"""
from __future__ import annotations

import pymupdf
import pytest

from tests import images as I
from tests.mcp_client import call_tool

BASE = "https://files.example.test"

# ---------------------------------------------------------------------------
# analyze_pdf_metadata
# ---------------------------------------------------------------------------

WORD = "Microsoft Word for Microsoft 365"
CONSISTENT = {
    "producer": WORD, "creator": WORD, "author": "Supplier SA",
    "creationDate": "D:20250301101500+00'00'", "modDate": "D:20250301101500+00'00'",
}


def _pdf(meta: dict, xmp: str | None = None, javascript: bool = False) -> bytes:
    doc = pymupdf.open()
    doc.new_page().insert_text((72, 72), "INVOICE 0001", fontsize=14)
    doc.set_metadata(meta)
    if xmp:
        doc.set_xml_metadata(xmp)
    if javascript:
        xref = doc.get_new_xref()
        doc.update_object(xref, "<</S/JavaScript/JS(app.alert(1))>>")
        doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{xref} 0 R")
    data = doc.tobytes()
    doc.close()
    return data


def _xmp(create_date: str) -> str:
    return (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/">'
        f"<xmp:CreateDate>{create_date}</xmp:CreateDate>"
        "</rdf:Description></rdf:RDF></x:xmpmeta>"
    )


def _meta(web, pdf: bytes):
    url = web.serve(f"{BASE}/invoice.pdf", pdf, "application/pdf")
    return call_tool("analyze_pdf_metadata", file_url=url, report_mode="full")


def test_metadata_consistent(web):
    res = _meta(web, _pdf(CONSISTENT))
    assert res.verdict == "METADATA_CONSISTENT", res.text
    assert "CONFIDENCE: 100/100" in res.text
    assert "CreationDate: 2025-03-01" in res.text
    assert "Author: Supplier SA" in res.text
    assert f"Creator: {WORD}" in res.text


def test_metadata_quick_mode_consistent(web):
    url = web.serve(f"{BASE}/invoice.pdf", _pdf(CONSISTENT), "application/pdf")
    res = call_tool("analyze_pdf_metadata", file_url=url)
    assert "METADATA_CONSISTENT" in res.text and "AUTHENTIC" in res.text


def test_moddate_long_after_creation_is_inconsistent(web):
    res = _meta(web, _pdf({**CONSISTENT, "creationDate": "D:20190301101500+00'00'"}))
    assert res.verdict == "METADATA_INCONSISTENT", res.text
    assert "days after CreationDate — document modified long after creation" in res.text


def test_moddate_before_creation_is_inconsistent(web):
    res = _meta(web, _pdf({**CONSISTENT, "modDate": "D:20240101101500+00'00'"}))
    assert res.verdict == "METADATA_INCONSISTENT", res.text
    assert "ModDate is BEFORE CreationDate" in res.text


def test_future_moddate_long_after_creation_is_suspicious(web):
    res = _meta(web, _pdf({**CONSISTENT, "modDate": "D:20990301101500+00'00'"}))
    assert res.verdict == "METADATA_SUSPICIOUS", res.text
    assert "ModDate is in the FUTURE" in res.text


def test_programmatic_producer_is_flagged(web):
    # +10 only: flagged, still below the 20-point INCONSISTENT threshold.
    res = _meta(web, _pdf({**CONSISTENT, "producer": "ReportLab PDF Library"}))
    assert "[Programmatic / Open-source generator]" in res.text
    assert "Producer is a programmatic PDF generator" in res.text
    assert res.verdict == "METADATA_CONSISTENT"
    assert "CONFIDENCE: 90/100" in res.text


def test_javascript_is_flagged(web):
    res = _meta(web, _pdf(CONSISTENT, javascript=True))
    assert res.verdict == "METADATA_INCONSISTENT", res.text
    assert "JavaScript detected" in res.text


def test_stripped_timestamps(web):
    res = _meta(web, _pdf({}))
    assert "No timestamps in metadata — may have been stripped" in res.text
    assert "Producer: not set [Unknown]" in res.text


def test_metadata_rejects_non_pdf(web):
    url = web.serve(f"{BASE}/invoice.pdf", b"GIF89a....", "application/pdf")
    res = call_tool("analyze_pdf_metadata", file_url=url)
    assert res.text == "[FakeSpotter Error] File is not a PDF (magic bytes check failed)"


@pytest.mark.parametrize("raw,shown", [
    ("D:20250301101500+00'00'", "2025-03-01 10:15:00 UTC"),
    ("D:20250301101500-03'00'", "2025-03-01 13:15:00 UTC"),
    ("D:20250301101500+05'30'", "2025-03-01 04:45:00 UTC"),
    ("D:20250301101500Z", "2025-03-01 10:15:00 UTC"),
    ("D:20250301101500", "2025-03-01 10:15:00 UTC"),
    ("D:202503011015", "2025-03-01 10:15:00 UTC"),
    ("D:20250301", "2025-03-01 00:00:00 UTC"),
])
def test_pdf_date_time_and_offset_parsed(web, raw, shown):
    res = _meta(web, _pdf({**CONSISTENT, "creationDate": raw, "modDate": raw}))
    assert f"CreationDate: {shown}" in res.text, res.text


def test_pdf_date_offsets_compared_in_utc(web):
    # 10:15 at -03:00 is 13:15 UTC: a ModDate of 12:15 UTC is BEFORE creation.
    res = _meta(web, _pdf({**CONSISTENT, "creationDate": "D:20250301101500-03'00'",
                           "modDate": "D:20250228121500Z"}))
    assert "ModDate is BEFORE CreationDate" in res.text, res.text


def test_xmp_create_date_mismatch_is_flagged(web):
    res = _meta(web, _pdf(CONSISTENT, xmp=_xmp("2023-01-10T09:00:00+00:00")))
    assert "XMP CreateDate" in res.text and "metadata inconsistency" in res.text, res.text


@pytest.mark.parametrize("xmp_date", [
    "2025-03-01T10:15:00+00:00",
    "2025-03-01T10:15:00Z",
    "2025-03-01T07:15:00-03:00",   # same instant, different offset
    "2025-03-01T10:15:00.000Z",
])
def test_xmp_create_date_consistent_is_not_flagged(web, xmp_date):
    res = _meta(web, _pdf(CONSISTENT, xmp=_xmp(xmp_date)))
    assert res.verdict == "METADATA_CONSISTENT", res.text
    assert "XMP CreateDate" not in res.text


def test_xmp_attribute_form_is_cross_checked(web):
    xmp = (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF '
        'xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:xmp="http://ns.adobe.com/xap/1.0/" '
        'xmp:CreateDate="2023-01-10T09:00:00Z"/>'
        "</rdf:RDF></x:xmpmeta>"
    )
    res = _meta(web, _pdf(CONSISTENT, xmp=xmp))
    assert "XMP CreateDate (2023-01-10)" in res.text, res.text


# ---------------------------------------------------------------------------
# inspect_qr_code
# ---------------------------------------------------------------------------

CBU = "2850590940090418135201"
PAY_URL = "https://pay.example.com/inv/0001"


def _qr(web, name: str, body: bytes, ctype: str, expected: str = "", mode: str = "quick"):
    url = web.serve(f"{BASE}/{name}", body, ctype)
    return call_tool("inspect_qr_code", file_url=url, expected_data=expected, report_mode=mode)


@pytest.fixture(scope="module")
def qr_png() -> bytes:
    return I.to_bytes(I.qr_image(CBU))


@pytest.fixture(scope="module")
def qr_pdf() -> bytes:
    return I.pdf_with_image(I.to_bytes(I.qr_image(PAY_URL)))


def test_qr_image_matches_expected(web, qr_png):
    res = _qr(web, "qr.png", qr_png, "image/png", expected=CBU, mode="full")
    assert res.verdict == "QR_MATCH", res.text
    assert "QR type detected: CBU (at image)" in res.text


def test_qr_image_mismatch(web, qr_png):
    other = CBU[:-1] + "9"
    res = _qr(web, "qr.png", qr_png, "image/png", expected=other, mode="full")
    assert res.verdict == "QR_MISMATCH", res.text
    assert f"Expected: {other}" in res.text
    assert f"Found:    {CBU}" in res.text


def test_qr_jpeg_image_decoded(web):
    body = I.to_bytes(I.qr_image(CBU), "JPEG", quality=90)
    res = _qr(web, "qr.jpg", body, "image/jpeg")
    assert f"QR_DECODED: {CBU}" in res.text, res.text


def test_qr_in_pdf_matches_case_insensitively(web, qr_pdf):
    res = _qr(web, "invoice.pdf", qr_pdf, "application/pdf", expected=PAY_URL.upper(), mode="full")
    assert res.verdict == "QR_MATCH", res.text
    assert "QR type detected: URL (at page 1)" in res.text
    assert "PDF scanned (1 pages with QR)" in res.text


def test_qr_in_pdf_mismatch(web, qr_pdf):
    res = _qr(web, "invoice.pdf", qr_pdf, "application/pdf",
              expected="https://pay.example.com/inv/0002", mode="full")
    assert res.verdict == "QR_MISMATCH", res.text


def test_qr_in_pdf_decoded_without_expected(web, qr_pdf):
    res = _qr(web, "invoice.pdf", qr_pdf, "application/pdf")
    assert f"QR_DECODED: {PAY_URL}" in res.text, res.text


def test_no_qr_in_image(web):
    res = _qr(web, "blank.png", I.to_bytes(I.blank_image()), "image/png", expected=CBU, mode="full")
    assert res.verdict == "NO_QR_FOUND", res.text


def test_no_qr_in_pdf(web):
    res = _qr(web, "plain.pdf", I.pdf_with_image(None), "application/pdf", expected=CBU)
    assert "NO_QR_FOUND: no QR code detected" in res.text, res.text


# ---------------------------------------------------------------------------
# correlate_documents
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def docs() -> dict[str, tuple[bytes, str]]:
    template = I.invoice_template()
    return {
        "template.png": (I.to_bytes(template), "image/png"),
        "edited.jpg": (I.to_bytes(I.near_duplicate(template), "JPEG", quality=85), "image/jpeg"),
        "unrelated.png": (I.to_bytes(I.unrelated_image()), "image/png"),
        "template.pdf": (I.pdf_with_image(I.to_bytes(template)), "application/pdf"),
    }


def _correlate(web, docs, names, **kw):
    urls = [web.serve(f"{BASE}/{n}", *docs[n]) for n in names]
    return call_tool("correlate_documents", document_urls=urls, report_mode="full", **kw)


def test_near_duplicates_share_assets(web, docs):
    res = _correlate(web, docs, ["template.png", "edited.jpg"])
    assert res.verdict == "ASSETS_SHARED", res.text
    assert "doc_01 ↔ doc_02: shared asset" in res.text


def test_unrelated_documents_do_not_correlate(web, docs):
    res = _correlate(web, docs, ["template.png", "unrelated.png"])
    assert res.verdict == "NO_CORRELATION", res.text
    assert "No shared visual assets detected" in res.text


def test_pdf_embedded_image_correlates_with_image(web, docs):
    # doc_01 unrelated, doc_02 PDF embedding the template, doc_03 edited JPEG.
    res = _correlate(web, docs, ["unrelated.png", "template.pdf", "edited.jpg"])
    assert res.verdict == "ASSETS_SHARED", res.text
    assert "doc_02 ↔ doc_03: shared asset" in res.text
    assert "doc_01 ↔" not in res.text
    assert "doc_02: 2 asset(s) extracted from template.pdf" in res.text


def test_failed_download_is_reported_not_correlated(web, docs):
    urls = [web.serve(f"{BASE}/template.png", *docs["template.png"]), f"{BASE}/missing.png"]
    res = call_tool("correlate_documents", document_urls=urls, report_mode="full")
    assert res.verdict == "NO_CORRELATION", res.text
    assert "doc_02: failed to process" in res.text


def test_correlate_needs_two_documents():
    res = call_tool("correlate_documents", document_urls=[f"{BASE}/a.png"])
    assert res.is_error


@pytest.mark.xfail(strict=True, reason=(
    "BUG: correlation_tools._correlate always uses the module constant HAMMING_THRESHOLD; "
    "the hamming_threshold parameter is only echoed in the report, so threshold=0 still "
    "matches a near-duplicate at distance 1-2."))
def test_hamming_threshold_parameter_is_applied(web, docs):
    res = _correlate(web, docs, ["template.png", "edited.jpg"], hamming_threshold=0)
    assert res.verdict == "NO_CORRELATION", res.text
