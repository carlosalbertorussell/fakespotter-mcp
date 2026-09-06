"""FakeSpotter — backends/hf_image.py
Hugging Face Inference API — two independent image classifiers.

Models:
  prithivMLmods/deepfake-detector-model-v1  (SiglipForImageClassification, 94.4% acc)
  dima806/deepfake_vs_real_image_detection   (ViT, binary real/fake)

Free with a HF personal access token: https://huggingface.co/settings/tokens
"""
from __future__ import annotations
import httpx
from .base import ClassifierBackend, BackendResult

HF_API = "https://api-inference.huggingface.co/models/{model}"

# (model_id, fake_label_fragment, weight)
HF_IMAGE_MODELS = [
    ("prithivMLmods/deepfake-detector-model-v1", "fake", 0.6),
    ("dima806/deepfake_vs_real_image_detection",  "Fake", 0.4),
]


class HFImageBackend(ClassifierBackend):
    name = "hf_image_ensemble"
    modality = "image"

    def __init__(self, hf_token: str) -> None:
        self._token = hf_token

    async def classify(self, data: bytes, mime_type: str = "image/jpeg") -> BackendResult:
        results = []
        async with httpx.AsyncClient(timeout=30) as client:
            for model_id, fake_label, weight in HF_IMAGE_MODELS:
                try:
                    resp = await client.post(
                        HF_API.format(model=model_id),
                        headers={
                            "Authorization": f"Bearer {self._token}",
                            "Content-Type": mime_type,
                        },
                        content=data,
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
                attribution="", error="All HF models failed",
            )
        total_w = sum(w for _, w, _ in valid)
        score = sum(s * w for s, w, _ in valid) / total_w
        confidence = total_w / sum(w for _, w, _ in HF_IMAGE_MODELS)
        return BackendResult(
            backend=self.name,
            score=round(score, 4),
            confidence=round(confidence, 4),
            attribution="",
            raw={"models": [{"model": m, "fake_score": s} for s, _, m in results]},
        )
