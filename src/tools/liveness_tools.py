"""
FakeSpotter — tools/liveness_tools.py
Identity Liveness + Face Match Validator (tool #26)

KYC in two steps via Sightengine BYOK (free tier available).

Step 1 — Liveness detection on selfie:
  Detects if the selfie shows a real person present in front of the camera,
  vs a printed photo, a screen replay, a 3D mask, or a deepfake frame.

Step 2 — Face match (when document_url is also provided):
  Extracts the face from the identity document and computes face similarity
  against the selfie. Returns FACE_MATCH or FACE_MISMATCH.

No new dependencies — Sightengine BYOK backend already in requirements.
Free tier: https://sightengine.com/pricing (1000 ops/month, no CC)

Verdicts:
  LIVENESS_CONFIRMED  — real person present (liveness check passed)
  LIVENESS_FAILED     — spoof detected (photo, screen, mask, deepfake)
  FACE_MATCH          — selfie face matches document face (similarity ≥ threshold)
  FACE_MISMATCH       — selfie face does not match document face
  FACE_NOT_DETECTED   — no face found in selfie or document
"""
from __future__ import annotations

from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter

SE_CHECK = "https://api.sightengine.com/1.0/check.json"
FACE_MATCH_THRESHOLD = 0.82  # similarity score (0-1) above which faces are considered matching


# ---------------------------------------------------------------------------
# Sightengine API calls
# ---------------------------------------------------------------------------

async def _se_liveness(img_bytes: bytes, mime: str,
                       api_user: str, api_secret: str) -> dict:
    """Check liveness of a selfie. Returns Sightengine response dict."""
    ext = "jpg" if "jpeg" in mime or "jpg" in mime else mime.split("/")[-1]
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            SE_CHECK,
            data={
                "models":     "liveness",
                "api_user":   api_user,
                "api_secret": api_secret,
            },
            files={"media": (f"selfie.{ext}", img_bytes, mime)},
        )
        resp.raise_for_status()
        return resp.json()


async def _se_face_similarity(img1: bytes, img2: bytes,
                               mime1: str, mime2: str,
                               api_user: str, api_secret: str) -> dict:
    """
    Compare two faces via Sightengine face-similarity endpoint.
    img1: selfie, img2: document face.
    """
    ext1 = "jpg" if "jpeg" in mime1 or "jpg" in mime1 else mime1.split("/")[-1]
    ext2 = "jpg" if "jpeg" in mime2 or "jpg" in mime2 else mime2.split("/")[-1]
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            SE_CHECK,
            data={
                "models":     "face-similarity",
                "api_user":   api_user,
                "api_secret": api_secret,
            },
            files={
                "media":  (f"selfie.{ext1}",   img1, mime1),
                "media2": (f"document.{ext2}", img2, mime2),
            },
        )
        resp.raise_for_status()
        return resp.json()


def _detect_mime(data: bytes, url: str) -> str:
    if data[:3] == b"\xff\xd8\xff": return "image/jpeg"
    if data[:8] == b"\x89PNG\r\n\x1a\n": return "image/png"
    if data[:4] == b"RIFF": return "image/webp"
    ext = url.rsplit(".", 1)[-1].lower().split("?")[0]
    return {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "webp": "image/webp"}.get(ext, "image/jpeg")


# ---------------------------------------------------------------------------
# Tool: validate_identity_liveness
# ---------------------------------------------------------------------------

class ValidateIdentityLivenessInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    selfie_url: str = Field(
        ...,
        description=(
            "Public URL of the selfie photo to check for liveness. "
            "The image must contain a human face. "
            "Supported: JPEG, PNG, WebP."
        ),
    )
    document_url: str = Field(
        "",
        description=(
            "Optional. Public URL of the identity document photo "
            "(passport photo page, ID card front). "
            "When provided, FakeSpotter computes face similarity between "
            "the document face and the selfie."
        ),
    )
    se_user:   str = Field(..., description="Sightengine API user (free tier at sightengine.com)")
    se_secret: str = Field(..., description="Sightengine API secret")
    face_match_threshold: float = Field(
        FACE_MATCH_THRESHOLD,
        ge=0.5, le=1.0,
        description="Minimum similarity score (0-1) to declare FACE_MATCH. Default: 0.82.",
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_validate_identity_liveness(mcp: FastMCP) -> None:

    @mcp.tool(
        name="validate_identity_liveness",
        annotations={
            "title": "Identity Liveness + Face Match Validator",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def validate_identity_liveness(params: ValidateIdentityLivenessInput) -> str:
        """
        KYC in two steps: liveness detection + optional face match.

        Step 1 — Liveness detection (always performed):
          Detects whether the selfie shows a real person present in front
          of the camera, vs a spoof attempt:
          - Printed photo held up to the camera
          - Screen replay (digital photo on phone/tablet)
          - 3D mask or silicone face
          - Deepfake or AI-generated face image

        Step 2 — Face match (when document_url is provided):
          Extracts the face from the identity document and computes
          similarity against the selfie. Returns FACE_MATCH or FACE_MISMATCH
          based on the configurable threshold (default: 0.82).

        Backend: Sightengine BYOK
          - liveness model: free tier, 1000 ops/month
          - face-similarity model: free tier, consumed ops per call
          Sign up at https://sightengine.com — no CC required.

        Verdicts:
          LIVENESS_CONFIRMED  — real person, no spoof detected
          LIVENESS_FAILED     — spoof detected (type surfaced in flags)
          FACE_MATCH          — selfie matches document (similarity ≥ threshold)
          FACE_MISMATCH       — selfie does not match document
          FACE_NOT_DETECTED   — no face found in selfie or document

        Args:
            params.selfie_url:  URL of the selfie photo
            params.document_url: URL of the identity document (optional)
            params.se_user:     Sightengine API user
            params.se_secret:   Sightengine API secret
            params.face_match_threshold: Similarity threshold (default 0.82)
            params.lang:        en | es
            params.report_mode: quick | full
        """
        try:
            flags:   list[str] = []
            verdicts: list[str] = []

            # Download selfie
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=30,
                headers={"User-Agent": "FakeSpotter/1.0 liveness-check"},
            ) as client:
                sresp = await client.get(params.selfie_url)
                sresp.raise_for_status()
                selfie_bytes = sresp.content
                selfie_mime  = _detect_mime(selfie_bytes, params.selfie_url)

            # ── Step 1: Liveness ─────────────────────────────────────────
            liveness_result = await _se_liveness(
                selfie_bytes, selfie_mime, params.se_user, params.se_secret
            )

            if liveness_result.get("status") != "success":
                err = liveness_result.get("error", {}).get("message", "Unknown error")
                return f"[FakeSpotter Error] Sightengine liveness check failed: {err}"

            liveness = liveness_result.get("liveness", {})
            score    = liveness.get("score", 0.0)         # 0 = spoof, 1 = live
            is_live  = score >= 0.5

            flags.append(f"Liveness score: {score:.3f} ({'live' if is_live else 'spoof'})")

            # Spoof type
            if not is_live:
                spoof_types = liveness.get("spoofTypes", [])
                if spoof_types:
                    flags.append(f"Spoof type detected: {', '.join(spoof_types)}")
                else:
                    flags.append("Spoof detected — type unspecified")
                verdicts.append("LIVENESS_FAILED")
            else:
                verdicts.append("LIVENESS_CONFIRMED")

            # Face presence in selfie
            faces = liveness_result.get("faces", [])
            if not faces:
                verdicts = ["FACE_NOT_DETECTED"]
                flags.append("No face detected in the selfie")

            # ── Step 2: Face match (optional) ────────────────────────────
            face_similarity_score: float | None = None

            if params.document_url and "LIVENESS_CONFIRMED" in verdicts:
                async with httpx.AsyncClient(
                    follow_redirects=True, timeout=30,
                    headers={"User-Agent": "FakeSpotter/1.0 face-match"},
                ) as client:
                    dresp = await client.get(params.document_url)
                    dresp.raise_for_status()
                    doc_bytes = dresp.content
                    doc_mime  = _detect_mime(doc_bytes, params.document_url)

                sim_result = await _se_face_similarity(
                    selfie_bytes, doc_bytes,
                    selfie_mime, doc_mime,
                    params.se_user, params.se_secret,
                )

                if sim_result.get("status") != "success":
                    err = sim_result.get("error", {}).get("message", "Unknown")
                    flags.append(f"Face similarity check failed: {err}")
                else:
                    sim = sim_result.get("similarity", {})
                    face_similarity_score = sim.get("score", 0.0)
                    threshold = params.face_match_threshold
                    flags.append(
                        f"Face similarity: {face_similarity_score:.3f} "
                        f"(threshold: {threshold:.2f})"
                    )
                    if face_similarity_score >= threshold:
                        verdicts.append("FACE_MATCH")
                    else:
                        verdicts.append("FACE_MISMATCH")

            # ── Aggregate verdict ─────────────────────────────────────────
            if "LIVENESS_FAILED" in verdicts:
                final_verdict = "LIVENESS_FAILED"
                trust = 0
            elif "FACE_NOT_DETECTED" in verdicts:
                final_verdict = "FACE_NOT_DETECTED"
                trust = 0
            elif "FACE_MISMATCH" in verdicts:
                final_verdict = "FACE_MISMATCH"
                trust = 0
            elif "FACE_MATCH" in verdicts:
                final_verdict = "FACE_MATCH"
                trust = 100
            else:
                final_verdict = "LIVENESS_CONFIRMED"
                trust = 85  # liveness passed but no face match performed

            findings = {
                "verdict":               final_verdict,
                "trust_score":           trust,
                "liveness_score":        score,
                "face_similarity_score": face_similarity_score,
                "face_match_threshold":  params.face_match_threshold,
                "steps_performed":       verdicts,
                "forensic_flags":        flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang)
                    if final_verdict in ("LIVENESS_CONFIRMED", "FACE_MATCH")
                    else i18n.t("verdict_fake", params.lang)
                    if final_verdict in ("LIVENESS_FAILED", "FACE_MISMATCH")
                    else i18n.t("verdict_uncertain", params.lang)
                )
                return f"{label} ({trust}/100) — {final_verdict} | {' | '.join(flags[:3])}"

            report = ForensicReporter.generate_report("validate_identity_liveness", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_validate_identity_liveness(mcp)
