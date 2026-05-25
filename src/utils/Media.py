"""
FakeSpotter — Media acquisition utilities.
Downloads images and video from URLs using httpx (images) and yt-dlp (video/audio).
All files are written to a secure tmp directory and cleaned up by the caller.
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
import yt_dlp


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_IMAGE_BYTES = 20 * 1024 * 1024   # 20 MB
MAX_VIDEO_BYTES = 200 * 1024 * 1024  # 200 MB
DOWNLOAD_TIMEOUT = 30                 # seconds

ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/png", "image/webp",
    "image/gif", "image/bmp", "image/tiff",
}

TMP_DIR = Path(os.environ.get("FAKESPOTTER_TMP", "/tmp/fakespotter"))
TMP_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http/https URLs are supported, got: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError("URL has no host/domain.")


def _safe_tmp_path(extension: str = "") -> Path:
    return TMP_DIR / f"{uuid.uuid4().hex}{extension}"


# ---------------------------------------------------------------------------
# Image download
# ---------------------------------------------------------------------------

async def download_image(url: str) -> tuple[bytes, str]:
    """
    Download an image from *url* and return (raw_bytes, content_type).
    Raises ValueError on oversized files or unsupported content types.
    """
    _validate_url(url)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=DOWNLOAD_TIMEOUT,
        headers={"User-Agent": "FakeSpotter/1.0 forensic-scanner"},
    ) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()

            content_type = resp.headers.get("content-type", "").split(";")[0].strip().lower()

            # Accept octet-stream too — some CDNs don't set proper image MIME
            if content_type not in ALLOWED_IMAGE_TYPES and "octet-stream" not in content_type:
                raise ValueError(
                    f"URL does not point to a supported image type. "
                    f"Got content-type: {content_type!r}"
                )

            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                total += len(chunk)
                if total > MAX_IMAGE_BYTES:
                    raise ValueError(
                        f"Image exceeds maximum allowed size "
                        f"({MAX_IMAGE_BYTES // 1024 // 1024} MB)."
                    )
                chunks.append(chunk)

    return b"".join(chunks), content_type


# ---------------------------------------------------------------------------
# Video download
# ---------------------------------------------------------------------------

def download_video(url: str, audio_only: bool = False) -> tuple[Path, dict]:
    """
    Download video (or audio-only) from *url* using yt-dlp.
    Returns (local_path, info_dict).
    Caller is responsible for deleting the file.
    """
    _validate_url(url)

    out_path = _safe_tmp_path()

    ydl_opts: dict = {
        "outtmpl": str(out_path) + ".%(ext)s",
        "quiet": True,
        "no_warnings": True,
        "noprogress": True,
        "max_filesize": MAX_VIDEO_BYTES,
    }

    if audio_only:
        ydl_opts["format"] = "bestaudio/best"
        ydl_opts["postprocessors"] = [{
            "key": "FFmpegExtractAudio",
            "preferredcodec": "mp3",
        }]
    else:
        # Prefer small format for forensics — we only need frames
        ydl_opts["format"] = "worstvideo[ext=mp4]/worst[ext=mp4]/worst"

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=True)
        info_clean = ydl.sanitize_info(info)

    # Find the downloaded file
    for ext in ("mp4", "webm", "mkv", "mp3", "m4a", "wav"):
        candidate = Path(str(out_path) + f".{ext}")
        if candidate.exists():
            return candidate, info_clean

    raise FileNotFoundError("yt-dlp did not produce an output file.")


# ---------------------------------------------------------------------------
# yt-dlp metadata only (no download)
# ---------------------------------------------------------------------------

def fetch_media_metadata(url: str) -> dict:
    """
    Extract metadata from a media URL without downloading the actual file.
    Returns the yt-dlp info dict.
    """
    _validate_url(url)

    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
    }

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info = ydl.extract_info(url, download=False)
        return ydl.sanitize_info(info)


# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------

def cleanup_file(path: Optional[Path]) -> None:
    """Silently remove a temporary file if it exists."""
    if path and path.exists():
        try:
            path.unlink()
        except OSError:
            pass
