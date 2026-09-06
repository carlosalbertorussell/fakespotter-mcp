"""FakeSpotter — backends/sightengine.py
Sightengine BYOK backend — AI-generated image + deepfake detection.

Free tier: https://sightengine.com/pricing (no CC required)
AI image detection = 5 ops/call. Free plan: 1000 ops/month = 200 checks.
"""
from __future__ import annotations
import httpx
from .base import ClassifierBackend, BackendResult

SE_ENDPOINT = "https://api.sightengine.com/1.0/check.json"


class SightengineImageBackend(ClassifierBackend):
    name = "sightengine_image"
    modality = "image"

    def __init__(self, api_user: str, api_secret: str) -> None:
        self._user = api_user
        self._secret = api_secret

    async def classify(self, data: bytes, mime_type: str = "image/jpeg") -> BackendResult:
        ext = "jpg" if "jpeg" in mime_type or "jpg" in mime_type else mime_type.split("/")[-1]
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    SE_ENDPOINT,
                    data={
                        "models": "ai-generated,deepfake",
                        "api_user": self._user,
                        "api_secret": self._secret,
                    },
                    files={"media": (f"media.{ext}", data, mime_type)},
                )
                resp.raise_for_status()
                result = resp.json()
            if result.get("status") != "success":
                return BackendResult(
                    backend=self.name, score=0.0, confidence=0.0, attribution="",
                    error=result.get("error", {}).get("message", "Unknown error"),
                )
            ai_score   = result.get("ai_generated", {}).get("ai_generated", 0.0)
            deep_score = result.get("deepfake", {}).get("score", 0.0)
            score = max(ai_score, deep_score)
            return BackendResult(
                backend=self.name,
                score=round(score, 4),
                confidence=1.0,
                attribution="",
                raw=result,
            )
        except Exception as exc:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="", error=str(exc),
            )
