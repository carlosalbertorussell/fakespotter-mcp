"""
FakeSpotter — tools/correlation_tools.py
Cross-Document Asset Correlation (tool #27)

Given a set of documents (images or PDFs), detects whether any share
the same embedded images or visual assets. A forged invoice template
reused across multiple fraud attempts leaves a perceptual hash fingerprint
that is detected even after minor edits, recolouring, or compression.

How it works:
  1. Downloads each document (image or PDF)
  2. Extracts visual assets:
       Images: used directly
       PDFs:   rasterized pages (via PyMuPDF) + embedded image objects
  3. Computes pHash (perceptual hash) and dHash (difference hash) per asset
  4. Builds a Hamming-distance similarity matrix across all pairs
  5. Flags pairs within the match threshold (default: ≤ 10 bits out of 64)
  6. Clusters correlated documents

Useful for:
  - Detecting a forged invoice template reused by the same fraud ring
  - Identifying copy-paste ID document fraud
  - Flagging documents that share stock photos or logos

Input: list of 2–10 document URLs (images or PDFs)
Output: similarity matrix + list of correlated pairs + cluster assignments

No new signal interpretation beyond perceptual hashing — human review
is still required to determine whether shared assets indicate fraud
vs legitimate reuse (same company logo, same header template).

Dependencies:
  imagehash>=4.3,<5  (perceptual hashing)
  Pillow             (already in requirements, used by imagehash)
  pymupdf>=1.24,<2   (already in requirements from S11, for PDF extraction)
"""
from __future__ import annotations

import io
import math
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter

HAMMING_THRESHOLD  = 10   # bits out of 64 — images closer than this are "similar"
MAX_DOCS           = 10
MAX_PAGES_PER_PDF  = 8
PDF_DPI            = 120  # lower DPI for speed; enough for pHash


# ---------------------------------------------------------------------------
# Image extraction
# ---------------------------------------------------------------------------

def _extract_images_from_bytes(data: bytes, url: str) -> list[bytes]:
    """
    Extract all visual assets from image or PDF bytes.
    Returns list of JPEG image bytes.
    """
    images: list[bytes] = []

    # PDF: rasterize pages + extract embedded images
    if data[:4] == b"%PDF" or url.lower().endswith(".pdf"):
        try:
            import fitz
            doc = fitz.open(stream=data, filetype="pdf")
            for page_num in range(min(doc.page_count, MAX_PAGES_PER_PDF)):
                page = doc[page_num]
                mat  = fitz.Matrix(PDF_DPI / 72, PDF_DPI / 72)
                pix  = page.get_pixmap(matrix=mat, colorspace=fitz.csRGB)
                images.append(pix.tobytes("jpeg"))
                # Also extract embedded image XObjects
                for img in doc.get_page_images(page_num):
                    try:
                        xref  = img[0]
                        base  = doc.extract_image(xref)
                        img_bytes = base.get("image", b"")
                        if len(img_bytes) > 1024:  # skip tiny images
                            images.append(img_bytes)
                    except Exception:
                        pass
            doc.close()
        except ImportError:
            pass
        return images

    # Otherwise treat as a single image
    images.append(data)
    return images


def _bytes_to_pil(img_bytes: bytes):
    """Convert raw bytes to PIL Image, handling common edge cases."""
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(img_bytes))
        img = img.convert("RGB")
        return img
    except Exception:
        return None


def _compute_hashes(img_bytes: bytes) -> tuple[int, int] | None:
    """Compute (pHash, dHash) as 64-bit integers. Returns None on failure."""
    try:
        import imagehash
        img = _bytes_to_pil(img_bytes)
        if img is None:
            return None
        ph = imagehash.phash(img)
        dh = imagehash.dhash(img)
        return int(str(ph), 16), int(str(dh), 16)
    except Exception:
        return None


def _hamming(a: int, b: int) -> int:
    """Compute Hamming distance between two 64-bit integers."""
    xor = a ^ b
    # Count set bits (popcount)
    count = 0
    while xor:
        count += xor & 1
        xor >>= 1
    return count


# ---------------------------------------------------------------------------
# Correlation engine
# ---------------------------------------------------------------------------

def _correlate(doc_assets: dict[str, list[tuple[int, int]]]) -> dict:
    """
    Given {doc_label: [(phash, dhash), ...]}, find correlated pairs.
    Returns similarity findings.
    """
    labels = list(doc_assets.keys())
    pairs: list[dict] = []
    correlated_docs: set[str] = set()

    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            a_label = labels[i]
            b_label = labels[j]
            a_hashes = doc_assets[a_label]
            b_hashes = doc_assets[b_label]

            min_dist_p = 64
            min_dist_d = 64
            best_pair  = None

            for ai, (ap, ad) in enumerate(a_hashes):
                for bi, (bp, bd) in enumerate(b_hashes):
                    dp = _hamming(ap, bp)
                    dd = _hamming(ad, bd)
                    combined = (dp + dd) // 2
                    if combined < (min_dist_p + min_dist_d) // 2:
                        min_dist_p = dp
                        min_dist_d = dd
                        best_pair  = (ai, bi)

            # Match if both pHash AND dHash are within threshold
            is_match = min_dist_p <= HAMMING_THRESHOLD and min_dist_d <= HAMMING_THRESHOLD

            if is_match:
                correlated_docs.add(a_label)
                correlated_docs.add(b_label)
                pairs.append({
                    "doc_a":         a_label,
                    "doc_b":         b_label,
                    "phash_distance": min_dist_p,
                    "dhash_distance": min_dist_d,
                    "asset_a_index":  best_pair[0] if best_pair else 0,
                    "asset_b_index":  best_pair[1] if best_pair else 0,
                    "confidence":     max(0, 100 - ((min_dist_p + min_dist_d) * 3)),
                })

    return {
        "correlated_pairs": pairs,
        "correlated_docs":  sorted(correlated_docs),
        "total_pairs_checked": (len(labels) * (len(labels) - 1)) // 2,
    }


# ---------------------------------------------------------------------------
# Tool: correlate_documents
# ---------------------------------------------------------------------------

class CorrelateDocumentsInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    document_urls: list[str] = Field(
        ...,
        description=(
            "List of 2–10 document URLs to correlate. "
            "Supported: JPEG, PNG, WebP (images) and PDF (all pages scanned). "
            "Each document is checked for shared visual assets against all others."
        ),
        min_length=2,
        max_length=MAX_DOCS,
    )
    hamming_threshold: int = Field(
        HAMMING_THRESHOLD,
        ge=0, le=20,
        description=(
            "Maximum Hamming distance (bits, 0–64) to consider two images as matching. "
            "Lower = stricter. Default: 10. "
            "Use 5 for exact duplicates, 10 for near-duplicates with minor edits."
        ),
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_correlate_documents(mcp: FastMCP) -> None:

    @mcp.tool(
        name="correlate_documents",
        annotations={
            "title": "Cross-Document Asset Correlator",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def correlate_documents(params: CorrelateDocumentsInput) -> str:
        """
        Detects whether a set of documents share the same visual assets
        (images, logos, templates) using perceptual hash correlation.

        Primary use case:
          A forged invoice template reused across multiple fraud attempts
          shares embedded images (company logo, header, signature block)
          even after minor edits, recolouring, or re-compression.

        Method:
          1. Downloads each document (image or PDF)
          2. Extracts all visual assets per document (PDF pages + embedded images)
          3. Computes pHash (perceptual hash) + dHash (difference hash) per asset
          4. Builds Hamming-distance matrix across all document pairs
          5. Flags pairs where both hashes are within the match threshold

        Verdicts:
          ASSETS_SHARED  — one or more document pairs share visual assets
          NO_CORRELATION — no shared assets detected at the given threshold

        IMPORTANT NOTE:
          Shared assets do not always indicate fraud. Documents from the same
          organisation may legitimately share logos, headers, or templates.
          Human review is required to interpret the correlation findings.

        Args:
            params.document_urls:    List of 2–10 document URLs
            params.hamming_threshold: Max bit distance for match (default 10)
            params.lang:             en | es
            params.report_mode:      quick | full
        """
        try:
            import imagehash  # noqa: F401 — trigger ImportError if not installed
        except ImportError:
            return (
                "[FakeSpotter Error] imagehash not installed. "
                "Add imagehash>=4.3,<5 to requirements.txt. "
                "Install with: pip install imagehash"
            )

        flags: list[str] = []
        doc_assets: dict[str, list[tuple[int, int]]] = {}

        # Download and hash all documents
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=30,
            headers={"User-Agent": "FakeSpotter/1.0 document-correlator"},
        ) as client:
            for idx, url in enumerate(params.document_urls, 1):
                label = f"doc_{idx:02d}"
                try:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    raw_images = _extract_images_from_bytes(resp.content, url)

                    hashes: list[tuple[int, int]] = []
                    for img_bytes in raw_images:
                        h = _compute_hashes(img_bytes)
                        if h is not None:
                            hashes.append(h)

                    doc_assets[label] = hashes
                    flags.append(f"{label}: {len(hashes)} asset(s) extracted from {url.split('/')[-1][:40]}")

                except Exception as e:
                    doc_assets[label] = []
                    flags.append(f"{label}: failed to process — {e}")

        # Correlate
        correlation = _correlate(doc_assets)
        pairs       = correlation["correlated_pairs"]

        if pairs:
            verdict = "ASSETS_SHARED"
            trust   = 0
            for pair in pairs:
                flags.append(
                    f"⚠ {pair['doc_a']} ↔ {pair['doc_b']}: "
                    f"shared asset (pHash dist={pair['phash_distance']}, "
                    f"dHash dist={pair['dhash_distance']}, "
                    f"confidence={pair['confidence']}%)"
                )
            flags.append(
                "NOTE: shared assets do not always indicate fraud — "
                "documents from the same organisation may share logos or templates"
            )
        else:
            verdict = "NO_CORRELATION"
            trust   = 100
            flags.append(
                f"No shared visual assets detected "
                f"(threshold: Hamming ≤ {params.hamming_threshold} bits)"
            )

        findings = {
            "verdict":              verdict,
            "trust_score":          trust,
            "documents_analysed":   len(doc_assets),
            "total_assets_hashed":  sum(len(v) for v in doc_assets.values()),
            "pairs_checked":        correlation["total_pairs_checked"],
            "correlated_pairs":     pairs,
            "correlated_docs":      correlation["correlated_docs"],
            "hamming_threshold":    params.hamming_threshold,
            "forensic_flags":       flags,
        }

        if params.report_mode == "quick":
            label = (
                i18n.t("verdict_fake", params.lang) if verdict == "ASSETS_SHARED"
                else i18n.t("verdict_authentic", params.lang)
            )
            summary = (
                f"{len(pairs)} correlated pair(s): "
                + "; ".join(f"{p['doc_a']}↔{p['doc_b']}" for p in pairs[:3])
                if pairs else "no shared assets detected"
            )
            return f"{label} ({trust}/100) — {verdict} | {summary}"

        report = ForensicReporter.generate_report("correlate_documents", findings, params.lang)
        return ForensicReporter.format_certificate(report, findings)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_correlate_documents(mcp)
