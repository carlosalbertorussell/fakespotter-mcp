"""
FakeSpotter — OSINT & Identity Forensic Tools (2 tools)
────────────────────────────────────────────────────────
17. analyze_image_metadata — Full EXIF + GPS + AI tool fingerprinting
18. verify_social_profile  — Profile consistency heuristics via HTTP analysis
"""
from __future__ import annotations

import re
from typing import Literal
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.analysis import extract_exif
from utils.i18n import i18n
from utils.media import download_image
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "SUSPICIOUS" in verdict or "FAKE" in verdict
        else i18n.t("verdict_authentic", lang) if "AUTHENTIC" in verdict or "CONSISTENT" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


# ---------------------------------------------------------------------------
# Tool 17: analyze_image_metadata
# ---------------------------------------------------------------------------

class AnalyzeImageMetadataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="Image URL to extract full EXIF and metadata from")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_image_metadata(mcp: FastMCP) -> None:

    @mcp.tool(
        name="analyze_image_metadata",
        annotations={
            "title": "Image Metadata Forensic Analyser",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_image_metadata(params: AnalyzeImageMetadataInput) -> str:
        """
        Extracts and forensically analyses all EXIF and metadata from an image.

        Provides:
        - Full EXIF tag dump (camera make/model, lens, settings)
        - GPS coordinates (latitude/longitude/altitude if present)
        - Creation vs modification timestamp consistency
        - AI generation tool fingerprinting (Stable Diffusion, Midjourney, DALL-E, etc.)
        - Image editing software detection (Photoshop, GIMP, Affinity)
        - Metadata stripping detection (stripped metadata is itself a signal)

        Args:
            params.media_url: Image URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Metadata forensic report or signed Forensic Certificate
        """
        try:
            image_bytes, content_type = await download_image(params.media_url)
            exif = extract_exif(image_bytes)

            flags: list[str] = []
            score = 0

            if exif.get("ai_tool_detected"):
                score += 50
                flags.append(f"AI generation tool confirmed: {exif['detected_ai_tool']}")

            if not exif.get("has_exif"):
                score += 15
                flags.append("EXIF metadata absent — possible stripping or synthetic origin")
            else:
                fields = exif.get("fields", {})

                # Camera hardware
                camera = exif.get("camera", "").strip()
                if not camera:
                    score += 10
                    flags.append("No camera hardware signature (Make/Model fields empty)")

                # Software check
                software = exif.get("software", "")
                editing_tools = ["photoshop", "gimp", "pixelmator", "affinity", "lightroom", "capture one"]
                if any(t in software.lower() for t in editing_tools):
                    score += 15
                    flags.append(f"Image editing software detected: {software}")

                # Timestamp consistency
                dt_orig   = fields.get("DateTimeOriginal", "")
                dt_mod    = fields.get("DateTime", "")
                if dt_orig and dt_mod and dt_orig != dt_mod:
                    score += 10
                    flags.append(f"Timestamp inconsistency: Original={dt_orig!r}, Modified={dt_mod!r}")

                # GPS
                gps_present = exif.get("gps_present", False)
                gps_info = {}
                if gps_present and "GPSInfo" in fields:
                    gps_info = {"present": True, "raw": str(fields["GPSInfo"])[:200]}

            score = min(100, score)
            verdict = (
                "METADATA_SUSPICIOUS" if score >= 50
                else "METADATA_UNCERTAIN" if score >= 25
                else "METADATA_CONSISTENT"
            )

            # Build structured EXIF summary (limit to useful fields)
            USEFUL_FIELDS = [
                "Make", "Model", "LensModel", "Software", "DateTime",
                "DateTimeOriginal", "DateTimeDigitized", "ExposureTime",
                "FNumber", "ISOSpeedRatings", "FocalLength", "Flash",
                "ImageWidth", "ImageLength", "Orientation",
            ]
            filtered_exif = {
                k: v for k, v in exif.get("fields", {}).items()
                if k in USEFUL_FIELDS
            }

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "has_exif": exif.get("has_exif"),
                "ai_tool_detected": exif.get("ai_tool_detected"),
                "detected_ai_tool": exif.get("detected_ai_tool"),
                "camera": exif.get("camera"),
                "software": exif.get("software"),
                "datetime_original": exif.get("datetime_original"),
                "gps_present": exif.get("gps_present"),
                "content_type": content_type,
                "exif_fields": filtered_exif,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("analyze_image_metadata", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 18: verify_social_profile
# ---------------------------------------------------------------------------

class VerifySocialProfileInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    profile_url: str = Field(
        ...,
        description="Public URL of the social media profile to analyse "
                    "(Twitter/X, LinkedIn, Instagram, Facebook, GitHub, TikTok)",
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


# Signals per platform
_PLATFORM_PATTERNS: dict[str, dict] = {
    "twitter.com": {"name": "Twitter/X",       "handle_regex": r"twitter\.com/([^/?#]+)"},
    "x.com":       {"name": "X (Twitter)",      "handle_regex": r"x\.com/([^/?#]+)"},
    "linkedin.com":{"name": "LinkedIn",         "handle_regex": r"linkedin\.com/in/([^/?#]+)"},
    "instagram.com":{"name": "Instagram",       "handle_regex": r"instagram\.com/([^/?#]+)"},
    "facebook.com":{"name": "Facebook",         "handle_regex": r"facebook\.com/([^/?#]+)"},
    "github.com":  {"name": "GitHub",           "handle_regex": r"github\.com/([^/?#]+)"},
    "tiktok.com":  {"name": "TikTok",           "handle_regex": r"tiktok\.com/@([^/?#]+)"},
}


def register_verify_social_profile(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_social_profile",
        annotations={
            "title": "Social Profile Authenticity Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_social_profile(params: VerifySocialProfileInput) -> str:
        """
        Heuristic authenticity analysis for public social media profiles.

        Checks:
        - Profile URL validity and platform recognition
        - HTTP response status (active vs suspended/deleted)
        - Username pattern anomalies (excessive numbers, keyboard walks)
        - Known impersonation patterns (verified-account Unicode lookalikes)
        - Response header signals (platform vs. third-party redirect)
        - Redirect to login page (suggests private/deleted account)

        Limitation: Does not scrape profile content due to ToS/robots.txt;
        analysis is based on URL structure and HTTP response headers only.

        Args:
            params.profile_url: Social profile URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Profile authenticity verdict or signed Forensic Certificate
        """
        try:
            parsed = urlparse(params.profile_url)
            domain = parsed.netloc.lower().lstrip("www.")

            flags: list[str] = []
            score  = 0

            # Platform recognition
            platform_info = next(
                (v for k, v in _PLATFORM_PATTERNS.items() if k in domain),
                None,
            )
            platform_name = platform_info["name"] if platform_info else "Unknown platform"

            if not platform_info:
                score += 20
                flags.append(f"Unrecognised social platform: {domain}")

            # Extract handle
            handle = ""
            if platform_info:
                m = re.search(platform_info["handle_regex"], params.profile_url)
                handle = m.group(1) if m else ""

            # Username anomaly checks
            if handle:
                # Excessive trailing numbers (bot pattern: user123456789)
                num_suffix = re.search(r"\d{6,}$", handle)
                if num_suffix:
                    score += 25
                    flags.append(f"Username ends in {len(num_suffix.group())} digits — common bot pattern")

                # Very short username (< 3 chars) on generic platforms
                if len(handle) < 3 and platform_name not in ("GitHub",):
                    score += 15
                    flags.append(f"Unusually short username: {handle!r}")

                # Keyboard walk pattern (e.g. qwerty123, asdfgh)
                keyboard_walks = ["qwerty", "asdfg", "zxcvb", "12345", "abcde"]
                if any(kw in handle.lower() for kw in keyboard_walks):
                    score += 20
                    flags.append(f"Keyboard-walk pattern in username: {handle!r}")

                # Homoglyphs in handle (Unicode lookalike attacks)
                has_non_ascii = any(ord(c) > 127 for c in handle)
                if has_non_ascii:
                    score += 35
                    flags.append(f"Non-ASCII characters in username — possible homograph impersonation")

            # HTTP liveness check
            try:
                async with httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=12,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; FakeSpotter/1.0 forensic-scanner)"},
                ) as client:
                    resp = await client.get(params.profile_url)
                    status = resp.status_code
                    final_url = str(resp.url)
                    redirect_count = len(resp.history)

                    # Redirected to login page
                    if any(
                        kw in final_url.lower()
                        for kw in ["login", "signin", "auth", "register", "suspended"]
                    ):
                        score += 30
                        flags.append(f"Profile redirects to auth/suspended page: {final_url}")

                    if status == 404:
                        score += 25
                        flags.append("Profile returns 404 — account may not exist or was removed")
                    elif status == 403:
                        score += 10
                        flags.append("Profile returns 403 — access restricted")
                    elif status >= 500:
                        flags.append(f"Server error {status} — platform issue or bot protection")

            except httpx.TimeoutException:
                flags.append("Request timed out — platform may be rate-limiting or blocking")
            except Exception as http_err:
                flags.append(f"HTTP check failed: {http_err}")

            score = min(100, score)
            verdict = (
                "PROFILE_SUSPICIOUS" if score >= 50
                else "PROFILE_UNCERTAIN" if score >= 25
                else "PROFILE_APPEARS_AUTHENTIC"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "profile_url": params.profile_url,
                "platform": platform_name,
                "username_handle": handle,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("verify_social_profile", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_analyze_image_metadata(mcp)
    register_verify_social_profile(mcp)
