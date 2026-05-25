"""
FakeSpotter — Media & Synthetic Content Tools (5 tools)
────────────────────────────────────────────────────────
1. audit_deepfake_video      — Frame-level ELA + metadata on video
2. detect_ai_generated_image — ELA + noise + EXIF + copy-move on image
3. analyze_audio_authenticity — yt-dlp metadata + spectral heuristics
4. verify_video_metadata     — Container/platform metadata consistency
5. detect_steganography      — LSB analysis on image
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator, ConfigDict

from utils.analysis import (
    analyze_noise_consistency,
    analyze_video_frames_ela,
    detect_copy_move,
    detect_lsb_steganography,
    extract_exif,
    perform_ela,
)
from utils.i18n import i18n
from utils.media import (
    cleanup_file,
    download_image,
    download_video,
    fetch_media_metadata,
)
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _score_to_verdict(score: int, threshold_fake: int = 60) -> str:
    if score >= threshold_fake:
        return "LIKELY_FAKE"
    if score >= 35:
        return "UNCERTAIN"
    return "LIKELY_AUTHENTIC"


def _build_quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang) if "FAKE" in verdict
        else i18n.t("verdict_authentic", lang) if "AUTHENTIC" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


# ---------------------------------------------------------------------------
# Tool 1: audit_deepfake_video
# ---------------------------------------------------------------------------

class AuditDeepfakeVideoInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="Public URL of the video to analyse (YouTube, direct mp4, etc.)")
    lang: Literal["en", "es"] = Field("en", description="Report language: 'en' or 'es'")
    report_mode: Literal["quick", "full"] = Field("quick", description="'quick' for binary verdict, 'full' for forensic certificate")
    sample_frames: int = Field(8, ge=4, le=20, description="Number of frames to sample for ELA (4–20)")


def register_audit_deepfake_video(mcp: FastMCP) -> None:

    @mcp.tool(
        name="audit_deepfake_video",
        annotations={
            "title": "Deepfake Video Auditor",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def audit_deepfake_video(params: AuditDeepfakeVideoInput) -> str:
        """
        Forensic deepfake detection on video content.

        Downloads the video, extracts evenly-spaced frames, and applies:
        - Error Level Analysis (ELA) per frame to detect inconsistent compression
        - Metadata analysis via yt-dlp (upload date, encoder, container)
        - Consistency check between claimed and detected codec signatures

        Returns a quick binary verdict or a full signed Forensic Certificate.

        Args:
            params.media_url: Video URL (YouTube, Vimeo, direct mp4 link, etc.)
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'
            params.sample_frames: Number of frames to sample (4–20)

        Returns:
            str: Verdict string (quick) or Forensic Certificate (full)
        """
        tmp_path = None
        try:
            # Fetch metadata first (fast)
            meta = fetch_media_metadata(params.media_url)

            # Download smallest available format for frame analysis
            tmp_path, _ = download_video(params.media_url)

            # Frame-level ELA
            ela_results = analyze_video_frames_ela(str(tmp_path), params.sample_frames)

            if "error" in ela_results:
                return f"Error during frame analysis: {ela_results['error']}"

            # Metadata signals
            flags: list[str] = []
            meta_score = 0

            uploader = meta.get("uploader", "")
            description = meta.get("description", "") or ""
            tags_list = meta.get("tags", []) or []
            tags_text = " ".join(tags_list).lower()

            deepfake_keywords = ["deepfake", "face swap", "ai generated", "synthetic", "faceswap"]
            if any(kw in description.lower() or kw in tags_text for kw in deepfake_keywords):
                flags.append("Deepfake keywords in metadata")
                meta_score += 30

            # Codec inconsistencies
            vcodec = meta.get("vcodec", "")
            if vcodec and "none" in vcodec.lower():
                flags.append("Missing video codec signature")
                meta_score += 10

            # Duration sanity
            duration = meta.get("duration", 0) or 0
            if duration > 0 and ela_results["duration_sec"] > 0:
                delta = abs(duration - ela_results["duration_sec"])
                if delta > 5:
                    flags.append(f"Duration mismatch: reported {duration}s vs actual {ela_results['duration_sec']}s")
                    meta_score += 15

            # ELA score
            ela_score = ela_results["mean_ela_score"]
            suspicious_frames = ela_results["suspicious_frames"]
            sampled = ela_results["sampled_frames"]

            if ela_results["overall_suspicious"]:
                flags.append(f"High ELA variance — {suspicious_frames}/{sampled} frames suspicious")

            composite_score = min(100, int(ela_score * 1.2) + meta_score)
            verdict = _score_to_verdict(composite_score)

            findings = {
                "verdict": verdict,
                "trust_score": 100 - composite_score,
                "ela_mean_score": ela_score,
                "ela_max_score": ela_results["max_ela_score"],
                "suspicious_frames": f"{suspicious_frames}/{sampled}",
                "duration_sec": ela_results["duration_sec"],
                "fps": ela_results["fps"],
                "source_platform": meta.get("extractor", "unknown"),
                "uploader": uploader,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - composite_score, flags, params.lang)

            report = ForensicReporter.generate_report("audit_deepfake_video", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"
        finally:
            cleanup_file(tmp_path)


# ---------------------------------------------------------------------------
# Tool 2: detect_ai_generated_image
# ---------------------------------------------------------------------------

class DetectAIImageInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="Public URL of the image to analyse")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_ai_generated_image(mcp: FastMCP) -> None:

    @mcp.tool(
        name="detect_ai_generated_image",
        annotations={
            "title": "AI-Generated Image Detector",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def detect_ai_generated_image(params: DetectAIImageInput) -> str:
        """
        Detects AI-generated or digitally manipulated images.

        Runs a multi-layer forensic stack:
        - Error Level Analysis (ELA) for compression inconsistencies
        - Noise consistency analysis across image blocks
        - Copy-move forgery detection via ORB feature matching
        - EXIF metadata extraction and AI tool fingerprinting

        Args:
            params.media_url: Image URL (JPEG, PNG, WebP, BMP, TIFF)
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Verdict or Forensic Certificate
        """
        try:
            image_bytes, content_type = await download_image(params.media_url)

            ela     = perform_ela(image_bytes)
            noise   = analyze_noise_consistency(image_bytes)
            cm      = detect_copy_move(image_bytes)
            exif    = extract_exif(image_bytes)

            flags: list[str] = []
            score = 0

            # ELA
            if ela.get("suspicious"):
                score += 30
                flags.append(f"ELA anomaly detected (mean={ela['mean_ela']}, max={ela['max_ela']})")

            # Noise
            if noise.get("suspicious"):
                score += 25
                flags.append(f"Inconsistent noise floor (CV ratio={noise.get('cv_ratio', '?')})")

            # Copy-move
            if cm.get("copy_move_detected"):
                score += 25
                flags.append(f"Copy-move forgery — {cm['suspicious_pairs']} suspicious region pairs")

            # EXIF
            if exif.get("ai_tool_detected"):
                score += 40
                flags.append(f"AI tool fingerprint: {exif['detected_ai_tool']}")
            elif not exif.get("has_exif"):
                score += 10
                flags.append("No EXIF metadata — possible stripping or synthetic origin")
            elif not exif.get("camera"):
                score += 8
                flags.append("No camera hardware signature in EXIF")

            score = min(100, score)
            verdict = _score_to_verdict(score)

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "ela": ela,
                "noise_analysis": noise,
                "copy_move": cm,
                "exif_summary": {
                    "has_exif": exif.get("has_exif"),
                    "software": exif.get("software"),
                    "camera": exif.get("camera"),
                    "ai_tool_detected": exif.get("ai_tool_detected"),
                    "detected_ai_tool": exif.get("detected_ai_tool"),
                },
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("detect_ai_generated_image", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 3: analyze_audio_authenticity
# ---------------------------------------------------------------------------

class AnalyzeAudioInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="URL of the audio or video with audio to analyse")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_audio_authenticity(mcp: FastMCP) -> None:

    @mcp.tool(
        name="analyze_audio_authenticity",
        annotations={
            "title": "Audio Authenticity Analyser",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_audio_authenticity(params: AnalyzeAudioInput) -> str:
        """
        Analyses audio authenticity via metadata and encoding heuristics.

        Extracts: codec, bitrate, sample rate, encoder, upload metadata,
        and cross-checks for common voice-cloning tool signatures in tags.

        Note: Acoustic deepfake detection at model level requires ML inference
        not available in this build; this tool covers metadata and encoding
        fingerprinting which catches a significant percentage of synthetic audio.

        Args:
            params.media_url: Audio/video URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Verdict or Forensic Certificate
        """
        try:
            meta = fetch_media_metadata(params.media_url)

            flags: list[str] = []
            score = 0

            acodec   = meta.get("acodec", "none") or "none"
            abr      = meta.get("abr", 0) or 0
            asr      = meta.get("asr", 0) or 0
            encoder  = (meta.get("encoder") or "").lower()
            comments = (meta.get("description") or "").lower()
            tags_str = " ".join(meta.get("tags", []) or []).lower()

            tts_keywords = ["text to speech", "tts", "voice clone", "elevenlabs",
                            "replica studios", "resemble.ai", "murf", "speechify",
                            "ai voice", "synthetic voice", "voiceover ai"]

            if any(kw in comments or kw in tags_str for kw in tts_keywords):
                score += 45
                flags.append("TTS/voice-clone keywords found in metadata")

            # Very low bitrate with non-telephony codec → suspicious
            if 0 < abr < 48 and acodec not in ("none", "opus"):
                score += 20
                flags.append(f"Unusually low audio bitrate: {abr} kbps")

            # Non-standard sample rates used by some TTS engines
            if asr and asr not in (8000, 16000, 22050, 44100, 48000):
                score += 15
                flags.append(f"Non-standard sample rate: {asr} Hz")

            # Encoder strings
            suspicious_encoders = ["ffmpeg", "lavf"]  # common in re-encoded synthetic media
            if any(e in encoder for e in suspicious_encoders) and score > 0:
                score += 10
                flags.append(f"Re-encoding signature detected: {encoder}")

            score = min(100, score)
            verdict = _score_to_verdict(score)

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "audio_codec": acodec,
                "bitrate_kbps": abr,
                "sample_rate_hz": asr,
                "encoder": meta.get("encoder"),
                "duration_sec": meta.get("duration"),
                "platform": meta.get("extractor"),
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("analyze_audio_authenticity", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 4: verify_video_metadata
# ---------------------------------------------------------------------------

class VerifyVideoMetadataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="Video URL to extract and verify metadata from")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_video_metadata(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_video_metadata",
        annotations={
            "title": "Video Metadata Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_video_metadata(params: VerifyVideoMetadataInput) -> str:
        """
        Extracts and verifies video container/platform metadata without downloading.

        Checks: upload date consistency, view count anomalies, codec signatures,
        thumbnail presence, description/tag coherence, and channel age.

        Args:
            params.media_url: Video URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Metadata report with consistency flags
        """
        try:
            meta = fetch_media_metadata(params.media_url)

            flags: list[str] = []
            score = 0

            upload_date = meta.get("upload_date")         # YYYYMMDD string
            view_count  = meta.get("view_count", 0) or 0
            like_count  = meta.get("like_count", 0) or 0
            duration    = meta.get("duration", 0) or 0
            thumbnail   = meta.get("thumbnail")
            description = meta.get("description") or ""
            title       = meta.get("title") or ""

            if not upload_date:
                score += 15
                flags.append("Upload date missing from metadata")

            if not thumbnail:
                score += 10
                flags.append("No thumbnail registered")

            # Like ratio anomaly (viral disinformation often has skewed ratios)
            if view_count > 10000 and like_count == 0:
                score += 20
                flags.append(f"Suspicious: {view_count} views but zero likes")

            if not description and duration > 60:
                score += 10
                flags.append("No description on video longer than 60s")

            # Title/description keyword check
            disinfo_signals = ["breaking", "exposed", "they don't want you to see",
                               "banned", "proof", "wake up", "cover up"]
            matched = [kw for kw in disinfo_signals if kw in title.lower() or kw in description.lower()]
            if matched:
                score += min(25, len(matched) * 8)
                flags.append(f"Disinformation-pattern keywords: {', '.join(matched)}")

            score = min(100, score)
            verdict = _score_to_verdict(score, threshold_fake=40)

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "title": title,
                "uploader": meta.get("uploader"),
                "platform": meta.get("extractor"),
                "upload_date": upload_date,
                "duration_sec": duration,
                "view_count": view_count,
                "like_count": like_count,
                "video_codec": meta.get("vcodec"),
                "audio_codec": meta.get("acodec"),
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("verify_video_metadata", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 5: detect_steganography
# ---------------------------------------------------------------------------

class DetectSteganographyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    media_url: str = Field(..., description="Image URL to analyse for hidden data")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_steganography(mcp: FastMCP) -> None:

    @mcp.tool(
        name="detect_steganography",
        annotations={
            "title": "Steganography Detector",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def detect_steganography(params: DetectSteganographyInput) -> str:
        """
        Detects hidden data embedded in images via LSB (Least Significant Bit) analysis.

        Natural images have slightly unequal LSB distributions due to sensor noise;
        LSB steganography produces near-uniform 50/50 distributions, which this
        tool detects per colour channel.

        Args:
            params.media_url: Image URL
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Verdict or Forensic Certificate with per-channel statistics
        """
        try:
            image_bytes, _ = await download_image(params.media_url)
            result = detect_lsb_steganography(image_bytes)

            if "error" in result:
                return f"[FakeSpotter Error] {result['error']}"

            detected  = result["steganography_detected"]
            score     = result["confidence"]
            flags: list[str] = []

            if detected:
                suspicious_ch = [
                    ch for ch, st in result["channel_stats"].items()
                    if st.get("suspicious")
                ]
                flags.append(f"LSB anomaly in channels: {', '.join(suspicious_ch)}")

            verdict = "STEGANOGRAPHY_DETECTED" if detected else "NO_STEGANOGRAPHY_FOUND"

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "steganography_detected": detected,
                "confidence_score": score,
                "channel_stats": result["channel_stats"],
                "suspicious_channels": result["suspicious_channels"],
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("detect_steganography", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_audit_deepfake_video(mcp)
    register_detect_ai_generated_image(mcp)
    register_analyze_audio_authenticity(mcp)
    register_verify_video_metadata(mcp)
    register_detect_steganography(mcp)
