"""
FakeSpotter — Media & Synthetic Content Tools (5 tools)
Sprint 5: detect_ai_generated_image and audit_deepfake_video upgraded
to neural ensemble backends (HF + Sightengine, BYOK, free-tier available).
Remaining 3 tools retain Layer-1 heuristics pending Sprint 6.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

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
from backends import HFImageBackend, SightengineImageBackend, run_ensemble


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _score_to_verdict(score: int, threshold_fake: int = 60) -> str:
    if score >= threshold_fake: return "LIKELY_FAKE"
    if score >= 35:             return "UNCERTAIN"
    return "LIKELY_AUTHENTIC"


def _build_quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "FAKE" in verdict or "AI_GENERATED" in verdict
        else i18n.t("verdict_authentic", lang) if "AUTHENTIC" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


def _image_backends(hf_token: str, se_user: str, se_secret: str) -> list:
    out = []
    if hf_token:                out.append(HFImageBackend(hf_token))
    if se_user and se_secret:   out.append(SightengineImageBackend(se_user, se_secret))
    return out


# ---------------------------------------------------------------------------
# Tool 1: audit_deepfake_video  (Sprint 5 — neural ensemble on key frames)
# ---------------------------------------------------------------------------

class AuditDeepfakeVideoInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    media_url:    str = Field(..., description="Public URL of the video (YouTube, direct mp4, etc.)")
    hf_token:     str = Field("", description="HuggingFace access token (free at hf.co/settings/tokens)")
    se_user:      str = Field("", description="Sightengine API user (optional)")
    se_secret:    str = Field("", description="Sightengine API secret (optional)")
    lang:         Literal["en", "es"] = Field("en")
    report_mode:  Literal["quick", "full"] = Field("quick")
    sample_frames: int = Field(8, ge=4, le=20)


def register_audit_deepfake_video(mcp: FastMCP) -> None:

    @mcp.tool(
        name="audit_deepfake_video",
        annotations={"title": "Deepfake Video Auditor",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": True},
    )
    async def audit_deepfake_video(params: AuditDeepfakeVideoInput) -> str:
        """
        Neural deepfake detection on video via frame sampling + ensemble classifiers.

        Extracts evenly-spaced frames, encodes each as JPEG, and submits to the
        neural ensemble (HuggingFace + Sightengine). Aggregates frame-level scores
        into a video-level verdict.

        Backends (BYOK, all free-tier available):
        - HF: prithivMLmods/deepfake-detector-model-v1, dima806/deepfake_vs_real_image_detection
        - Sightengine: AI-generated + deepfake model

        Falls back to ELA + metadata heuristics if no backend keys are provided.
        """
        import io
        tmp_path = None
        try:
            meta = fetch_media_metadata(params.media_url)
            backends = _image_backends(params.hf_token, params.se_user, params.se_secret)
            flags: list[str] = []

            if backends:
                # Neural path: sample frames, run ensemble on each
                tmp_path, _ = download_video(params.media_url)
                ela_results = analyze_video_frames_ela(str(tmp_path), params.sample_frames)

                if "error" in ela_results:
                    return f"[FakeSpotter] Frame extraction error: {ela_results['error']}"

                # Extract frames as JPEG bytes
                import cv2
                cap = cv2.VideoCapture(str(tmp_path))
                total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                indices = [int(i * total_frames / params.sample_frames)
                           for i in range(params.sample_frames)]
                frame_scores: list[float] = []

                for idx in indices:
                    cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
                    ret, frame = cap.read()
                    if not ret:
                        continue
                    ok, buf = cv2.imencode(".jpg", frame)
                    if not ok:
                        continue
                    frame_bytes = buf.tobytes()
                    result = await run_ensemble(backends, frame_bytes, "image/jpeg")
                    frame_scores.append(result.score)

                cap.release()

                if not frame_scores:
                    return "[FakeSpotter Error] No frames could be extracted"

                video_score = sum(frame_scores) / len(frame_scores)
                suspicious_frames = sum(1 for s in frame_scores if s >= 0.65)
                score = int(video_score * 100)

                if video_score >= 0.65:   verdict = "LIKELY_AI_GENERATED"
                elif video_score >= 0.35: verdict = "UNCERTAIN"
                else:                     verdict = "LIKELY_AUTHENTIC"

                if suspicious_frames > 0:
                    flags.append(f"{suspicious_frames}/{len(frame_scores)} frames flagged as AI-generated")

                findings = {
                    "verdict": verdict,
                    "trust_score": 100 - score,
                    "detection_engine": "neural_ensemble",
                    "video_score": round(video_score, 4),
                    "frames_sampled": len(frame_scores),
                    "frames_flagged": suspicious_frames,
                    "frame_scores": [round(s, 3) for s in frame_scores],
                    "source_platform": meta.get("extractor", "unknown"),
                    "forensic_flags": flags,
                }

            else:
                # Fallback: original ELA + metadata path
                tmp_path, _ = download_video(params.media_url)
                ela_results = analyze_video_frames_ela(str(tmp_path), params.sample_frames)
                if "error" in ela_results:
                    return f"[FakeSpotter] {ela_results['error']}"
                ela_score = ela_results["mean_ela_score"]
                suspicious_frames = ela_results["suspicious_frames"]
                sampled = ela_results["sampled_frames"]
                if ela_results["overall_suspicious"]:
                    flags.append(f"ELA: {suspicious_frames}/{sampled} frames suspicious")
                flags.append("LAYER_1_FALLBACK: no neural backend keys — accuracy limited")
                composite_score = min(100, int(ela_score * 1.2))
                verdict = _score_to_verdict(composite_score)
                score = composite_score
                findings = {
                    "verdict": verdict, "trust_score": 100 - score,
                    "detection_engine": "layer1_fallback",
                    "ela_mean_score": ela_score,
                    "source_platform": meta.get("extractor", "unknown"),
                    "forensic_flags": flags,
                }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)
            report = ForensicReporter.generate_report("audit_deepfake_video", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"
        finally:
            cleanup_file(tmp_path)


# ---------------------------------------------------------------------------
# Tool 2: detect_ai_generated_image  (Sprint 5 — neural ensemble)
# ---------------------------------------------------------------------------

class DetectAIImageInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    media_url:   str = Field(..., description="Public URL of the image (JPEG, PNG, WebP)")
    hf_token:    str = Field("", description="HuggingFace token (free at hf.co/settings/tokens)")
    se_user:     str = Field("", description="Sightengine API user (optional)")
    se_secret:   str = Field("", description="Sightengine API secret (optional)")
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_ai_generated_image(mcp: FastMCP) -> None:

    @mcp.tool(
        name="detect_ai_generated_image",
        annotations={"title": "AI-Generated Image Detector",
                     "readOnlyHint": True, "destructiveHint": False,
                     "idempotentHint": True, "openWorldHint": True},
    )
    async def detect_ai_generated_image(params: DetectAIImageInput) -> str:
        """
        Detects AI-generated or deepfake images using a neural ensemble.

        Backends (BYOK, all free-tier available):
        - HF Inference API: prithivMLmods/deepfake-detector-model-v1 (94.4% acc)
          and dima806/deepfake_vs_real_image_detection — free HF token.
        - Sightengine: AI-generated + deepfake models — free tier, BYOK.

        Provide at least one backend key. Falls back to Layer-1 heuristics
        (ELA + noise + EXIF) with an explicit disclaimer if no keys are given.
        """
        try:
            image_bytes, content_type = await download_image(params.media_url)
            mime = content_type or "image/jpeg"
            backends = _image_backends(params.hf_token, params.se_user, params.se_secret)
            flags: list[str] = []

            if backends:
                result = await run_ensemble(backends, image_bytes, mime)
                score  = int(result.score * 100)
                verdict = result.verdict
                if result.backends_failed:
                    flags.append(f"Unavailable backends: {', '.join(result.backends_failed)}")
                if result.attribution:
                    flags.append(f"Likely generator: {result.attribution}")
                findings = {
                    "verdict": verdict,
                    "trust_score": 100 - score,
                    "detection_engine": "neural_ensemble",
                    **result.to_findings(),
                    "forensic_flags": flags,
                }
            else:
                # Layer-1 fallback
                ela   = perform_ela(image_bytes)
                noise = analyze_noise_consistency(image_bytes)
                exif  = extract_exif(image_bytes)
                score = 0
                if ela.get("suspicious"):          score += 30; flags.append("ELA anomaly")
                if noise.get("suspicious"):        score += 25; flags.append("Noise inconsistency")
                if exif.get("ai_tool_detected"):   score += 40; flags.append(f"AI tool: {exif.get('detected_ai_tool')}")
                elif not exif.get("has_exif"):     score += 10; flags.append("No EXIF")
                score = min(100, score)
                verdict = _score_to_verdict(score)
                flags.append("LAYER_1_FALLBACK: no neural backend keys — accuracy limited against modern generators")
                findings = {
                    "verdict": verdict, "trust_score": 100 - score,
                    "detection_engine": "layer1_fallback",
                    "forensic_flags": flags,
                }

            if params.report_mode == "quick":
                return _build_quick(verdict, 100 - score, flags, params.lang)
            report = ForensicReporter.generate_report("detect_ai_generated_image", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tools 3-5: unchanged (Layer-1, pending Sprint 6)
# ---------------------------------------------------------------------------

class AnalyzeAudioInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    media_url:   str = Field(..., description="URL of the audio or video to analyse")
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_audio_authenticity(mcp: FastMCP) -> None:
    import re
    @mcp.tool(name="analyze_audio_authenticity",
              annotations={"title": "Audio Authenticity Analyser",
                           "readOnlyHint": True, "destructiveHint": False,
                           "idempotentHint": True, "openWorldHint": True})
    async def analyze_audio_authenticity(params: AnalyzeAudioInput) -> str:
        """
        Metadata + encoding heuristics for audio authenticity.
        Note: neural audio deepfake detection coming in Sprint 6.
        """
        try:
            meta    = fetch_media_metadata(params.media_url)
            flags:  list[str] = []
            score   = 0
            acodec  = meta.get("acodec", "none") or "none"
            abr     = meta.get("abr", 0) or 0
            asr     = meta.get("asr", 0) or 0
            encoder = (meta.get("encoder") or "").lower()
            comments= (meta.get("description") or "").lower()
            tags_str= " ".join(meta.get("tags", []) or []).lower()
            tts_kw  = ["text to speech","tts","voice clone","elevenlabs","replica studios",
                       "resemble.ai","murf","speechify","ai voice","synthetic voice"]
            if any(kw in comments or kw in tags_str for kw in tts_kw):
                score += 45; flags.append("TTS keywords in metadata")
            if 0 < abr < 48 and acodec not in ("none","opus"):
                score += 20; flags.append(f"Low bitrate: {abr} kbps")
            if asr and asr not in (8000,16000,22050,44100,48000):
                score += 15; flags.append(f"Non-standard sample rate: {asr} Hz")
            if any(e in encoder for e in ["ffmpeg","lavf"]) and score > 0:
                score += 10; flags.append(f"Re-encode signature: {encoder}")
            score   = min(100, score)
            verdict = _score_to_verdict(score)
            findings= {"verdict": verdict, "trust_score": 100-score,
                       "detection_engine": "layer1_metadata",
                       "audio_codec": acodec, "bitrate_kbps": abr,
                       "sample_rate_hz": asr, "forensic_flags": flags}
            if params.report_mode == "quick":
                return _build_quick(verdict, 100-score, flags, params.lang)
            report  = ForensicReporter.generate_report("analyze_audio_authenticity", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)
        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


class VerifyVideoMetadataInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    media_url:   str = Field(..., description="Video URL")
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_verify_video_metadata(mcp: FastMCP) -> None:
    @mcp.tool(name="verify_video_metadata",
              annotations={"title": "Video Metadata Verifier",
                           "readOnlyHint": True, "destructiveHint": False,
                           "idempotentHint": True, "openWorldHint": True})
    async def verify_video_metadata(params: VerifyVideoMetadataInput) -> str:
        """Container/platform metadata consistency check. Pending Sprint 6 neural upgrade."""
        try:
            meta = fetch_media_metadata(params.media_url)
            flags: list[str] = []
            score = 0
            upload_date= meta.get("upload_date")
            view_count = meta.get("view_count", 0) or 0
            like_count = meta.get("like_count", 0) or 0
            duration   = meta.get("duration", 0) or 0
            thumbnail  = meta.get("thumbnail")
            description= meta.get("description") or ""
            title      = meta.get("title") or ""
            if not upload_date:  score += 15; flags.append("Upload date missing")
            if not thumbnail:    score += 10; flags.append("No thumbnail")
            if view_count > 10000 and like_count == 0:
                score += 20; flags.append(f"{view_count} views, zero likes")
            if not description and duration > 60:
                score += 10; flags.append("No description on video >60s")
            disinfo = ["breaking","exposed","they don't want you to see","banned","proof"]
            matched = [kw for kw in disinfo if kw in title.lower() or kw in description.lower()]
            if matched: score += min(25, len(matched)*8); flags.append(f"Disinfo keywords: {', '.join(matched)}")
            score   = min(100, score)
            verdict = _score_to_verdict(score, threshold_fake=40)
            findings= {"verdict": verdict, "trust_score": 100-score,
                       "title": title, "uploader": meta.get("uploader"),
                       "platform": meta.get("extractor"),
                       "upload_date": upload_date, "duration_sec": duration,
                       "view_count": view_count, "like_count": like_count,
                       "forensic_flags": flags}
            if params.report_mode == "quick":
                return _build_quick(verdict, 100-score, flags, params.lang)
            report  = ForensicReporter.generate_report("verify_video_metadata", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)
        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


class DetectSteganographyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    media_url:   str = Field(..., description="Image URL")
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_detect_steganography(mcp: FastMCP) -> None:
    @mcp.tool(name="detect_steganography",
              annotations={"title": "Steganography Detector",
                           "readOnlyHint": True, "destructiveHint": False,
                           "idempotentHint": True, "openWorldHint": True})
    async def detect_steganography(params: DetectSteganographyInput) -> str:
        """LSB steganography detection. Layer-1 heuristic — no neural equivalent available."""
        try:
            image_bytes, _ = await download_image(params.media_url)
            result   = detect_lsb_steganography(image_bytes)
            if "error" in result:
                return f"[FakeSpotter Error] {result['error']}"
            detected = result["steganography_detected"]
            score    = result["confidence"]
            flags    = []
            if detected:
                suspicious_ch = [ch for ch, st in result["channel_stats"].items() if st.get("suspicious")]
                flags.append(f"LSB anomaly in channels: {', '.join(suspicious_ch)}")
            verdict  = "STEGANOGRAPHY_DETECTED" if detected else "NO_STEGANOGRAPHY_FOUND"
            findings = {"verdict": verdict, "trust_score": 100-score,
                        "steganography_detected": detected,
                        "channel_stats": result["channel_stats"],
                        "forensic_flags": flags}
            if params.report_mode == "quick":
                return _build_quick(verdict, 100-score, flags, params.lang)
            report   = ForensicReporter.generate_report("detect_steganography", findings, params.lang)
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
