"""FakeSpotter — backends/sightengine_audio.py
Sightengine BYOK backend — AI-generated music detection.

Uses Sightengine's `ai-music` model (BETA as of 2026).
Trained on Suno, Udio, Riffusion, and other major generators.
Works best on audio without vocals; accuracy drops on vocal-heavy tracks.

Free tier: https://sightengine.com/pricing (no CC required)
AI music detection = 5 ops/call. Free plan: 1000 ops/month = 200 checks.

Attribution: when detected, returns the likely generator
(suno, udio, riffusion, musicgen, stable_audio, etc.).
"""
from __future__ import annotations
import httpx
from .base import ClassifierBackend, BackendResult

SE_ENDPOINT = "https://api.sightengine.com/1.0/check.json"

# Generator labels Sightengine may return in the attribution field
KNOWN_GENERATORS = {
    "suno", "udio", "riffusion", "musicgen", "stable_audio",
    "yue", "minimax", "mureka", "mubert",
}


class SightengineAudioBackend(ClassifierBackend):
    name = "sightengine_audio"
    modality = "music"

    def __init__(self, api_user: str, api_secret: str) -> None:
        self._user   = api_user
        self._secret = api_secret

    async def classify(self, data: bytes, mime_type: str = "audio/wav") -> BackendResult:
        ext = mime_type.split("/")[-1] if "/" in mime_type else "wav"
        ext = {"mpeg": "mp3", "mp4": "m4a"}.get(ext, ext)

        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    SE_ENDPOINT,
                    data={
                        "models":     "ai-music",
                        "api_user":   self._user,
                        "api_secret": self._secret,
                    },
                    files={"media": (f"audio.{ext}", data, mime_type)},
                )
                resp.raise_for_status()
                result = resp.json()

            if result.get("status") != "success":
                return BackendResult(
                    backend=self.name, score=0.0, confidence=0.0,
                    attribution="",
                    error=result.get("error", {}).get("message", "Unknown error"),
                )

            # ai_music block: {"ai_generated": 0.95, "attribution": "suno"}
            ai_music = result.get("ai_music", {})
            score    = float(ai_music.get("ai_generated", 0.0))
            raw_attr = str(ai_music.get("attribution", "")).lower()
            attribution = raw_attr if raw_attr in KNOWN_GENERATORS else ""

            return BackendResult(
                backend=self.name,
                score=round(score, 4),
                confidence=1.0,
                attribution=attribution,
                raw=result,
            )
        except Exception as exc:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="", error=str(exc),
            )
