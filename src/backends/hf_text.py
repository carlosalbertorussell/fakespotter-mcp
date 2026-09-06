"""FakeSpotter — backends/hf_text.py
HuggingFace Inference API — two independent AI-text classifiers.

Models:
  Hello-SimpleAI/chatgpt-detector-roberta
      RoBERTa fine-tuned on HC3 dataset. Labels: "ChatGPT" / "Human". Weight 0.6.

  openai-community/roberta-base-openai-detector
      RoBERTa trained by OpenAI on GPT-2 outputs. Labels: "Fake" / "Real". Weight 0.4.
      Older model; lower accuracy on post-GPT-3 text.

KNOWN LIMITATIONS (always surfaced in the certificate):
  - Both models trained on pre-2024 data; accuracy degrades on newer LLM outputs.
  - Not reliable for edited AI text or mixed human/AI content.
  - Spanish text will produce unreliable results (English-trained models).
  - Not suitable as sole evidence for misconduct allegations.

Free via HF Inference API: https://huggingface.co/settings/tokens
"""
from __future__ import annotations
import httpx
from .base import ClassifierBackend, BackendResult

HF_API = "https://api-inference.huggingface.co/models/{model}"

HF_TEXT_MODELS = [
    ("Hello-SimpleAI/chatgpt-detector-roberta",       "ChatGPT", 0.6),
    ("openai-community/roberta-base-openai-detector", "Fake",    0.4),
]

LIMITATIONS = (
    "Neural models trained pre-2024. Accuracy degrades on newer LLMs, "
    "edited text, and non-English content."
)


class HFTextBackend(ClassifierBackend):
    name = "hf_text_ensemble"
    modality = "text"

    def __init__(self, hf_token: str) -> None:
        self._token = hf_token

    async def classify(self, data: bytes, mime_type: str = "text/plain") -> BackendResult:
        text = data.decode("utf-8", errors="replace")
        results = []

        async with httpx.AsyncClient(timeout=30) as client:
            for model_id, ai_label, weight in HF_TEXT_MODELS:
                try:
                    resp = await client.post(
                        HF_API.format(model=model_id),
                        headers={"Authorization": f"Bearer {self._token}"},
                        json={"inputs": text},
                    )
                    resp.raise_for_status()
                    raw = resp.json()
                    # HF text classification returns [[{"label":..,"score":..},...]]
                    classes = raw[0] if isinstance(raw, list) and raw else raw
                    ai_score = next(
                        (c["score"] for c in classes
                         if ai_label.lower() in c["label"].lower()),
                        0.0,
                    )
                    results.append((ai_score, weight, model_id))
                except Exception as exc:
                    results.append((0.0, 0.0, f"ERROR:{exc}"))

        valid = [(s, w, m) for s, w, m in results if w > 0]
        if not valid:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution="", error="All HF text models failed",
            )
        total_w = sum(w for _, w, _ in valid)
        score = sum(s * w for s, w, _ in valid) / total_w
        confidence = total_w / sum(w for _, w, _ in HF_TEXT_MODELS)
        return BackendResult(
            backend=self.name,
            score=round(score, 4),
            confidence=round(confidence, 4),
            attribution=LIMITATIONS,
            raw={"models": [{"model": m, "ai_score": s} for s, _, m in results]},
        )
