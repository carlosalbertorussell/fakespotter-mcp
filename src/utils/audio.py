"""FakeSpotter — utils/audio.py
Audio format detection and conversion for the neural deepfake detection pipeline.

Supported input formats (all converted to WAV 16kHz mono PCM before HF submission):
  - WAV  (audio/wav)                  — direct
  - MP3  (audio/mpeg)                 — direct or convert
  - FLAC (audio/flac)                 — direct
  - OGG/Opus (audio/ogg, audio/opus)  — WhatsApp & Telegram voice messages
  - M4A/AAC  (audio/mp4, audio/m4a)  — iOS voice memos
  - WebM/Opus (audio/webm)            — web recordings
  - AMR      (audio/amr)              — legacy mobile recordings
  - 3GP      (audio/3gpp)             — legacy mobile

Conversion uses ffmpeg (bundled in the Docker image).
Output: WAV, 16kHz, mono, 16-bit PCM — the format Wav2Vec2 models expect.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

# Formats the HF Inference API accepts natively (no conversion needed)
HF_NATIVE_MIMES = {"audio/wav", "audio/flac", "audio/flac"}

# MIME type detection from magic bytes
AUDIO_MAGIC: list[tuple[bytes, str, str]] = [
    (b"RIFF",           "audio/wav",   ".wav"),   # WAV (RIFF header)
    (b"fLaC",           "audio/flac",  ".flac"),  # FLAC
    (b"ID3",            "audio/mpeg",  ".mp3"),   # MP3 with ID3 tag
    (b"\xff\xfb",       "audio/mpeg",  ".mp3"),   # MP3 frame sync
    (b"\xff\xf3",       "audio/mpeg",  ".mp3"),   # MP3 frame sync variant
    (b"OggS",           "audio/ogg",   ".ogg"),   # OGG (Opus, Vorbis)
    (b"\x1aE\xdf\xa3",  "audio/webm",  ".webm"),  # WebM / MKV
    (b"#!AMR",          "audio/amr",   ".amr"),   # AMR-NB
    (b"#!AMR-WB",       "audio/amr",   ".amr"),   # AMR-WB
]

# URL extension to MIME fallback
EXT_TO_MIME: dict[str, str] = {
    ".wav":  "audio/wav",
    ".flac": "audio/flac",
    ".mp3":  "audio/mpeg",
    ".ogg":  "audio/ogg",
    ".oga":  "audio/ogg",
    ".opus": "audio/opus",
    ".m4a":  "audio/mp4",
    ".aac":  "audio/aac",
    ".webm": "audio/webm",
    ".amr":  "audio/amr",
    ".3gp":  "audio/3gpp",
    ".3gpp": "audio/3gpp",
    ".mp4":  "audio/mp4",
}

# Human-readable format descriptions for certificates
MIME_LABELS: dict[str, str] = {
    "audio/wav":   "WAV PCM",
    "audio/flac":  "FLAC",
    "audio/mpeg":  "MP3",
    "audio/ogg":   "OGG/Opus (WhatsApp/Telegram)",
    "audio/opus":  "Opus",
    "audio/mp4":   "M4A/AAC (iOS voice memo)",
    "audio/aac":   "AAC",
    "audio/webm":  "WebM/Opus",
    "audio/amr":   "AMR (legacy mobile)",
    "audio/3gpp":  "3GP (legacy mobile)",
}


def detect_mime(data: bytes, url: str = "", content_type: str = "") -> str:
    """
    Detect audio MIME type in priority order:
    1. Magic bytes (most reliable)
    2. Content-Type header from HTTP response
    3. URL file extension
    4. Default to audio/wav
    """
    # 1. Magic bytes
    for magic, mime, _ in AUDIO_MAGIC:
        if data[:len(magic)] == magic:
            return mime

    # 2. Content-Type header (strip params like "; codecs=opus")
    if content_type:
        ct = content_type.split(";")[0].strip().lower()
        if ct.startswith("audio/"):
            return ct

    # 3. URL extension
    suffix = Path(url.split("?")[0]).suffix.lower()
    if suffix in EXT_TO_MIME:
        return EXT_TO_MIME[suffix]

    return "audio/wav"


def needs_conversion(mime: str) -> bool:
    """Returns True if the format needs conversion to WAV before HF submission."""
    return mime not in HF_NATIVE_MIMES


def to_wav_16k_mono(data: bytes, source_mime: str = "audio/wav") -> tuple[bytes, str]:
    """
    Convert audio bytes to WAV 16kHz mono 16-bit PCM using ffmpeg.
    Returns (wav_bytes, format_label) or raises RuntimeError if ffmpeg fails.

    Target spec: 16kHz mono PCM16 — the format Wav2Vec2 models expect.
    """
    if not needs_conversion(source_mime):
        return data, MIME_LABELS.get(source_mime, source_mime)

    # Determine ffmpeg input format hint
    fmt_map: dict[str, str] = {
        "audio/ogg":   "ogg",
        "audio/opus":  "ogg",
        "audio/mp4":   "mp4",
        "audio/aac":   "aac",
        "audio/webm":  "webm",
        "audio/amr":   "amr",
        "audio/3gpp":  "3gp",
        "audio/mpeg":  "mp3",
        "audio/flac":  "flac",
    }
    input_fmt = fmt_map.get(source_mime, "")

    with tempfile.TemporaryDirectory() as tmpdir:
        ext = {v: k.split("/")[1] for k, v in fmt_map.items()}.get(input_fmt, "bin")
        in_path  = Path(tmpdir) / f"input.{input_fmt or 'bin'}"
        out_path = Path(tmpdir) / "output.wav"
        in_path.write_bytes(data)

        cmd = ["ffmpeg", "-y"]
        if input_fmt:
            cmd += ["-f", input_fmt]
        cmd += [
            "-i", str(in_path),
            "-ar", "16000",   # 16kHz sample rate (Wav2Vec2 standard)
            "-ac", "1",       # mono
            "-c:a", "pcm_s16le",  # 16-bit PCM little-endian
            str(out_path),
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")[-500:]
            raise RuntimeError(f"ffmpeg conversion failed: {stderr}")

        wav_bytes = out_path.read_bytes()

    label = MIME_LABELS.get(source_mime, source_mime)
    return wav_bytes, label


async def download_audio_direct(url: str) -> tuple[bytes, str]:
    """
    Download audio from a direct URL (non-yt-dlp: WhatsApp, Telegram, S3, etc.)
    Returns (audio_bytes, detected_mime).
    """
    import httpx
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=30,
        headers={"User-Agent": "FakeSpotter/1.0 audio-forensic-scanner"},
    ) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.content
        content_type = resp.headers.get("content-type", "")
        mime = detect_mime(data, url, content_type)
        return data, mime
