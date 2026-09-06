"""FakeSpotter — backends/hf_music.py
HuggingFace Inference API — AI-generated music classifier.

Model:
  AI-Music-Detection/ai_music_detection_large_60s
      Audio Classification, 0.1B params.
      Trained specifically to detect AI-generated music (Suno, Udio, MusicGen, etc.).
      Processes 60-second segments; longer files are chunked automatically.
      Free via HF Inference API: https://huggingface.co/settings/tokens

IMPORTANT DISTINCTION from HFAudioBackend:
  - HFAudioBackend detects synthetic/cloned VOICE (speech deepfakes).
  - HFMusicBackend detects AI-GENERATED MUSIC (Suno, Udio, MusicGen, Riffusion).
  These are different models, different training data, different signals.
"""
from __future__ import annotations
import asyncio
import httpx
from .base import ClassifierBackend, BackendResult

HF_API = "https://api-inference.huggingface.co/models/{model}"
HF_MUSIC_MODEL = "AI-Music-Detection/ai_music_detection_large_60s"


class HFMusicBackend(ClassifierBackend):
    name = "hf_music"
    modality = "music"

    def __init__(self, hf_token: str) -> None:
        self._token = hf_token

    async def classify(self, data: bytes, mime_type: str = "audio/wav") -> BackendResult:
        try:
            async with httpx.AsyncClient(timeout=90) as client:
                resp = await client.post(
                    HF_API.format(model=HF_MUSIC_MODEL),
                    headers={
                        "Authorization": f"Bearer {self._token}",
                        "Content-Type": "audio/wav",
                    },
                    content=data,
                )
                if resp.status_code == 503:
                    # Model cold-starting — retry once
                    await asyncio.sleep(10)
                    resp = await client.post(
                        HF_API.format(model=HF_MUSIC_MODEL),
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Content-Type": "audio/wav",
                        },
                        content=data,
                    )
                resp.raise_for_status()
                classes = resp.json()

            # Expected labels: "ai_generated" / "human" (or similar)
            ai_score = next(
                (c["score"] for c in classes
                 if any(kw in c["label"].lower()
                        for kw in ("ai", "generated", "fake", "synthetic"))),
                0.0,
            )
            return BackendResult(
                backend=self.name,
                score=round(ai_score, 4),
                confidence=1.0,
                attribution="",
                raw={"model": HF_MUSIC_MODEL, "classes": classes},
            )
        except Exception as exc:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="", error=str(exc),
            )
