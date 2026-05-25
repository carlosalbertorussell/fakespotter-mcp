"""
FakeSpotter — Core forensic analysis utilities.
Implements: ELA, noise analysis, copy-move detection, LSB steganography,
EXIF extraction, text statistics, and file integrity.
"""
from __future__ import annotations

import hashlib
import io
import math
import re
import struct
from typing import Any

import cv2
import numpy as np
from PIL import Image, ExifTags, UnidentifiedImageError


# ---------------------------------------------------------------------------
# Image loading
# ---------------------------------------------------------------------------

def load_image_bytes(data: bytes) -> Image.Image:
    """Load PIL Image from raw bytes, raising ValueError on failure."""
    try:
        img = Image.open(io.BytesIO(data))
        img.load()
        return img
    except (UnidentifiedImageError, Exception) as exc:
        raise ValueError(f"Cannot decode image: {exc}") from exc


# ---------------------------------------------------------------------------
# Error Level Analysis
# ---------------------------------------------------------------------------

def perform_ela(image_bytes: bytes, quality: int = 92) -> dict[str, Any]:
    """
    Error Level Analysis — detects regions saved at different compression levels,
    which is a strong indicator of compositing or local manipulation.

    Authentic images have a uniform ELA surface; manipulated regions
    stand out with significantly higher (or lower) residuals.
    """
    try:
        original = load_image_bytes(image_bytes).convert("RGB")

        # Re-save at known quality
        buf = io.BytesIO()
        original.save(buf, "JPEG", quality=quality)
        buf.seek(0)
        recompressed = Image.open(buf).convert("RGB")

        orig_arr = np.array(original, dtype=np.float32)
        rec_arr  = np.array(recompressed, dtype=np.float32)

        diff = np.abs(orig_arr - rec_arr)
        mean_ela = float(np.mean(diff))
        max_ela  = float(np.max(diff))
        std_ela  = float(np.std(diff))

        # Empirically: authentic JPEGs < 8, suspicious > 15, likely tampered > 25
        score = min(100, int(mean_ela * 4))
        suspicious = mean_ela > 12

        return {
            "mean_ela": round(mean_ela, 2),
            "max_ela":  round(max_ela, 2),
            "std_ela":  round(std_ela, 2),
            "manipulation_score": score,
            "suspicious": suspicious,
        }
    except Exception as exc:
        return {"error": str(exc), "manipulation_score": 0, "suspicious": False}


# ---------------------------------------------------------------------------
# Noise consistency analysis
# ---------------------------------------------------------------------------

def analyze_noise_consistency(image_bytes: bytes) -> dict[str, Any]:
    """
    Measures local noise variance across image blocks.
    Authentic photos from a single sensor show consistent noise texture;
    composited or AI-generated regions often have a different noise floor.
    """
    try:
        img = load_image_bytes(image_bytes).convert("RGB")
        arr = np.array(img)
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY).astype(np.float32)

        h, w = gray.shape
        block_size = max(min(h, w) // 10, 32)

        laplacian_kernel = np.array([[-1, -1, -1],
                                     [-1,  8, -1],
                                     [-1, -1, -1]], dtype=np.float32)

        variances: list[float] = []
        for y in range(0, h - block_size, block_size):
            for x in range(0, w - block_size, block_size):
                block = gray[y:y + block_size, x:x + block_size]
                filtered = cv2.filter2D(block, -1, laplacian_kernel)
                variances.append(float(np.var(filtered)))

        if not variances:
            return {"noise_consistent": True, "suspicious": False, "cv_ratio": 0.0}

        mean_v = float(np.mean(variances))
        std_v  = float(np.std(variances))
        cv_ratio = std_v / (mean_v + 1e-6)

        # CV > 0.85 suggests heterogeneous noise sources
        suspicious = cv_ratio > 0.85

        return {
            "noise_consistent": not suspicious,
            "variance_mean": round(mean_v, 2),
            "variance_std":  round(std_v, 2),
            "cv_ratio":      round(cv_ratio, 3),
            "suspicious":    suspicious,
        }
    except Exception as exc:
        return {"noise_consistent": True, "suspicious": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Copy-move forgery detection
# ---------------------------------------------------------------------------

def detect_copy_move(image_bytes: bytes) -> dict[str, Any]:
    """
    Detects copy-move forgery via ORB feature matching.
    Cloned/pasted regions share almost-identical feature descriptors
    at different spatial locations.
    """
    try:
        img = load_image_bytes(image_bytes).convert("RGB")
        arr = np.array(img)
        gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)

        orb = cv2.ORB_create(nfeatures=600)
        kps, descs = orb.detectAndCompute(gray, None)

        if descs is None or len(descs) < 20:
            return {"copy_move_detected": False, "confidence": 0, "suspicious_pairs": 0}

        bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
        matches = bf.knnMatch(descs, descs, k=3)

        suspicious = 0
        for group in matches:
            if len(group) >= 2:
                m, n = group[0], group[1]
                if m.trainIdx != m.queryIdx and m.distance < 28:
                    # Check spatial separation to exclude trivial self-matches
                    pt1 = kps[m.queryIdx].pt
                    pt2 = kps[m.trainIdx].pt
                    dist = math.hypot(pt1[0] - pt2[0], pt1[1] - pt2[1])
                    if dist > 30:
                        suspicious += 1

        ratio = suspicious / max(len(kps), 1)
        detected = ratio > 0.08

        return {
            "copy_move_detected": detected,
            "suspicious_pairs": suspicious,
            "confidence": min(100, int(ratio * 250)),
        }
    except Exception as exc:
        return {"copy_move_detected": False, "confidence": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# LSB Steganography detection
# ---------------------------------------------------------------------------

def detect_lsb_steganography(image_bytes: bytes) -> dict[str, Any]:
    """
    Analyses the distribution of Least Significant Bits across channels.
    Natural images have slightly non-uniform LSBs; LSB-embedded payloads
    produce artificially uniform (near 50/50) distributions.
    """
    try:
        img = load_image_bytes(image_bytes).convert("RGB")
        arr = np.array(img)

        channels = {"R": arr[:, :, 0], "G": arr[:, :, 1], "B": arr[:, :, 2]}
        stats: dict[str, Any] = {}
        suspicious_channels = 0

        for name, ch in channels.items():
            lsbs = (ch & 1).flatten()
            ones_ratio = float(np.mean(lsbs))
            # Natural: 0.45–0.55; steganographic: very close to 0.50000
            deviation = abs(ones_ratio - 0.5)
            suspicious_ch = deviation < 0.005
            if suspicious_ch:
                suspicious_channels += 1
            stats[name] = {
                "ones_ratio": round(ones_ratio, 5),
                "deviation_from_50pct": round(deviation, 5),
                "suspicious": suspicious_ch,
            }

        detected = suspicious_channels >= 2

        return {
            "steganography_detected": detected,
            "suspicious_channels": suspicious_channels,
            "channel_stats": stats,
            "confidence": min(100, suspicious_channels * 40),
        }
    except Exception as exc:
        return {"steganography_detected": False, "error": str(exc), "confidence": 0}


# ---------------------------------------------------------------------------
# EXIF metadata extraction
# ---------------------------------------------------------------------------

_AI_TOOLS = [
    "stable diffusion", "midjourney", "dall-e", "firefly",
    "imagen", "flux", "ideogram", "adobe firefly", "bing image",
    "canva", "runway", "pika", "sora",
]

def extract_exif(image_bytes: bytes) -> dict[str, Any]:
    """
    Extracts and decodes all EXIF tags.
    Flags AI-generation tools found in Software/Artist/Comment fields.
    """
    try:
        img = load_image_bytes(image_bytes)
        raw_exif = img._getexif()  # type: ignore[attr-defined]

        if not raw_exif:
            return {"has_exif": False, "fields": {}, "ai_tool_detected": False}

        fields: dict[str, str] = {}
        for tag_id, value in raw_exif.items():
            tag = ExifTags.TAGS.get(tag_id, str(tag_id))
            try:
                fields[tag] = str(value) if not isinstance(value, bytes) \
                              else value.decode("utf-8", errors="replace")
            except Exception:
                fields[tag] = repr(value)

        # Check fingerprint fields for AI tools
        fingerprint_text = " ".join([
            fields.get("Software", ""),
            fields.get("Artist", ""),
            fields.get("ImageDescription", ""),
            fields.get("XPComment", ""),
        ]).lower()

        ai_detected = any(t in fingerprint_text for t in _AI_TOOLS)
        detected_tool = next((t for t in _AI_TOOLS if t in fingerprint_text), None)

        return {
            "has_exif": True,
            "fields": fields,
            "ai_tool_detected": ai_detected,
            "detected_ai_tool": detected_tool,
            "software": fields.get("Software", "Unknown"),
            "camera": f"{fields.get('Make', '')} {fields.get('Model', '')}".strip(),
            "datetime_original": fields.get("DateTimeOriginal", fields.get("DateTime", "Unknown")),
            "gps_present": "GPSInfo" in fields,
        }
    except Exception as exc:
        return {"has_exif": False, "fields": {}, "ai_tool_detected": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# File integrity
# ---------------------------------------------------------------------------

def calculate_hashes(content: bytes) -> dict[str, str]:
    """Returns MD5, SHA-256, and SHA-512 digests for a byte payload."""
    return {
        "md5":    hashlib.md5(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha512": hashlib.sha512(content).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Text AI-generation heuristics
# ---------------------------------------------------------------------------

def analyze_text_authenticity(text: str) -> dict[str, Any]:
    """
    Heuristic analysis of text for AI-generation markers.

    Signals used:
    - Burstiness: human writing has higher variance in sentence length
    - Vocabulary richness (Type-Token Ratio)
    - Filler phrase density (known GPT/Claude patterns)
    - Paragraph uniformity
    - Punctuation variance
    """
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    sentences = [s for s in sentences if len(s) > 3]

    words = re.findall(r"\b\w+\b", text.lower())
    word_count = len(words)

    if word_count < 30 or len(sentences) < 3:
        return {"error": "Text too short for reliable analysis (min 30 words, 3 sentences)", "score": 0}

    # Burstiness — human text has higher σ/μ of sentence lengths
    sent_lens = [len(re.findall(r"\b\w+\b", s)) for s in sentences]
    mean_len = float(np.mean(sent_lens))
    std_len  = float(np.std(sent_lens))
    burstiness = std_len / (mean_len + 1e-6)

    # Vocabulary richness
    unique_words = len(set(words))
    ttr = unique_words / word_count  # Type-Token Ratio

    # Known AI filler phrases
    ai_fillers = [
        "certainly", "of course", "absolutely", "furthermore", "moreover",
        "in conclusion", "it is worth noting", "it's important to note",
        "delve into", "it's crucial", "as an ai", "i cannot", "I need to",
        "let's explore", "in this context", "it is essential",
    ]
    filler_count = sum(1 for f in ai_fillers if f in text.lower())
    filler_density = filler_count / max(word_count / 100, 1)

    # Paragraph uniformity
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    para_lens = [len(p) for p in paragraphs]
    para_cv = float(np.std(para_lens)) / (float(np.mean(para_lens)) + 1e-6) if para_lens else 0

    # AI score: low burstiness + high filler + uniform paragraphs → AI
    ai_score = 0
    if burstiness < 0.35:    ai_score += 30
    elif burstiness < 0.55:  ai_score += 15
    if ttr < 0.40:           ai_score += 20
    if filler_density > 1.5: ai_score += 25
    elif filler_density > 0.8: ai_score += 12
    if para_cv < 0.25:       ai_score += 15

    ai_score = min(100, ai_score)
    verdict = "LIKELY_AI" if ai_score >= 55 else ("UNCERTAIN" if ai_score >= 35 else "LIKELY_HUMAN")

    return {
        "verdict": verdict,
        "ai_probability_score": ai_score,
        "word_count": word_count,
        "sentence_count": len(sentences),
        "burstiness": round(burstiness, 3),
        "vocabulary_richness_ttr": round(ttr, 3),
        "filler_phrase_count": filler_count,
        "filler_density": round(filler_density, 2),
        "paragraph_uniformity": round(1 - para_cv, 3),
        "flags": {
            "low_burstiness":   burstiness < 0.35,
            "low_vocabulary":   ttr < 0.40,
            "high_filler":      filler_density > 1.5,
            "uniform_paragraphs": para_cv < 0.25,
        },
    }


# ---------------------------------------------------------------------------
# Video frame ELA (for deepfake analysis)
# ---------------------------------------------------------------------------

def analyze_video_frames_ela(
    video_path: str,
    sample_count: int = 8,
) -> dict[str, Any]:
    """
    Extracts evenly-spaced frames from a video and runs ELA on each.
    Returns aggregate statistics and per-frame results.
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return {"error": f"Cannot open video: {video_path}"}

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps          = cap.get(cv2.CAP_PROP_FPS)
    duration     = total_frames / fps if fps > 0 else 0

    if total_frames < 1:
        cap.release()
        return {"error": "Video has no readable frames"}

    sample_positions = [
        int(i * total_frames / sample_count)
        for i in range(sample_count)
    ]

    frame_results: list[dict] = []
    for pos in sample_positions:
        cap.set(cv2.CAP_PROP_POS_FRAMES, pos)
        ret, frame = cap.read()
        if not ret:
            continue
        # Encode frame as JPEG bytes for ELA
        _, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 95])
        frame_bytes = buf.tobytes()
        ela = perform_ela(frame_bytes)
        frame_results.append({
            "frame_index": pos,
            "timestamp_sec": round(pos / fps, 2) if fps > 0 else 0,
            **ela,
        })

    cap.release()

    if not frame_results:
        return {"error": "No frames could be sampled"}

    scores = [f["manipulation_score"] for f in frame_results if "manipulation_score" in f]
    mean_score  = float(np.mean(scores)) if scores else 0
    max_score   = float(np.max(scores))  if scores else 0
    suspicious_frames = sum(1 for f in frame_results if f.get("suspicious"))

    return {
        "total_frames": total_frames,
        "fps": round(fps, 2),
        "duration_sec": round(duration, 2),
        "sampled_frames": len(frame_results),
        "suspicious_frames": suspicious_frames,
        "mean_ela_score": round(mean_score, 1),
        "max_ela_score":  round(max_score, 1),
        "overall_suspicious": suspicious_frames >= max(1, sample_count // 3),
        "frame_detail": frame_results,
    }
