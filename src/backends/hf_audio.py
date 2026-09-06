"""FakeSpotter — backends/hf_audio.py
HuggingFace Inference API — two independent audio deepfake classifiers.

Models:
  koyelog/deepfake-voice-detector-sota
      Wav2Vec2 + BiGRU + Multi-Head Attention, trained on ASVspoof 2021.
      Output: probability 0-1 (1 = fake). Weight 0.6.

  motheecreator/Deepfake-audio-detection
      Wav2Vec2 fine-tuned for TTS/VC detection. Apache 2.0. Weight 0.4.

Free via HF Inference API: https://huggingface.co/settings/tokens

Supported input formats (all converted to WAV 16kHz mono before submission):
  WAV, MP3, FLAC — native
  OGG/Opus       — WhatsApp & Telegram voice messages
  M4A/AAC        — iOS voice memos
  WebM/Opus      — web recordings, browser media recorder
  AMR, 3GP       — legacy mobile formats

Conversion uses ffmpeg (bundled in the Docker image).
"""
from __future__ import annotations
import asyncio
import httpx
from .base import ClassifierBackend, BackendResult
from utils.audio import to_wav_16k_mono, MIME_LABELS

HF_API = "https://api-inference.huggingface.co/models/{model}"

HF_AUDIO_MODELS = [
    ("koyelog/deepfake-voice-detector-sota",   "fake", 0.6),
    ("motheecreator/Deepfake-audio-detection", "FAKE", 0.4),
]


class HFAudioBackend(ClassifierBackend):
    name = "hf_audio_ensemble"
    modality = "audio"

    def __init__(self, hf_token: str) -> None:
        self._token = hf_token

    async def classify(self, data: bytes, mime_type: str = "audio/wav") -> BackendResult:
        # Always convert to WAV 16kHz mono — the format both Wav2Vec2 models expect
        try:
            wav_data, format_label = to_wav_16k_mono(data, mime_type)
        except RuntimeError as exc:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="",
                error=f"Audio conversion failed: {exc}",
            )

        results = []
        async with httpx.AsyncClient(timeout=60) as client:
            for model_id, fake_label, weight in HF_AUDIO_MODELS:
                try:
                    resp = await client.post(
                        HF_API.format(model=model_id),
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Content-Type": "audio/wav",
                        },
                        content=wav_data,
                    )
                    if resp.status_code == 503:
                        # Model cold-starting — retry once after brief wait
                        await asyncio.sleep(8)
                        resp = await client.post(
                            HF_API.format(model=model_id),
                            headers={
                                "Authorization": f"Bearer {self._token}",
                                "Content-Type": "audio/wav",
                            },
                            content=wav_data,
                        )
                    resp.raise_for_status()
                    classes = resp.json()
                    fake_score = next(
                        (c["score"] for c in classes
                         if fake_label.lower() in c["label"].lower()),
                        0.0,
                    )
                    results.append((fake_score, weight, model_id))
                except Exception as exc:
                    results.append((0.0, 0.0, f"ERROR:{exc}"))

        valid = [(s, w, m) for s, w, m in results if w > 0]
        if not valid:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="", error="All HF audio models failed",
            )
        total_w = sum(w for _, w, _ in valid)
        score = sum(s * w for s, w, _ in valid) / total_w
        confidence = total_w / sum(w for _, w, _ in HF_AUDIO_MODELS)
        return BackendResult(
            backend=self.name,
            score=round(score, 4),
            confidence=round(confidence, 4),
            attribution=f"Input format: {format_label}",
            raw={"models": [{"model": m, "fake_score": s} for s, _, m in results],
                 "input_format": format_label},
        )
