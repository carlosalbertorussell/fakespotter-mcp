"""FakeSpotter — backends/synthid.py
SynthID-Text watermark detector (Google DeepMind).

WHAT IT DETECTS:
  Text generated with the Kirchenbauer/SynthID green-token watermarking scheme.
  It does NOT detect arbitrary AI-generated text.

SCOPE:
  - Only works when the original generation used SynthID watermarking.
  - ChatGPT, Claude, Gemini in production do NOT watermark their output.
  - Useful for: internal systems that generate with SynthID active,
    or to confirm absence of a known watermark scheme.

IMPLEMENTATION:
  SynthID-Text requires local execution with access to the generator model's
  tokenizer and logits — not callable via the standard HF Inference API.
  This backend uses a custom HF Inference Endpoint if configured.
  See docs/synthid-setup.md for setup instructions.
"""
from __future__ import annotations
import httpx
from .base import ClassifierBackend, BackendResult

SYNTHID_NOTE = (
    "SynthID detects Kirchenbauer-scheme watermarks ONLY. "
    "A negative result does NOT confirm human authorship. "
    "ChatGPT/Claude/Gemini production outputs are not watermarked."
)


class SynthIDTextBackend(ClassifierBackend):
    name = "synthid_text"
    modality = "text"

    def __init__(self, endpoint_url: str, hf_token: str = "") -> None:
        """
        endpoint_url: HF Inference Endpoint URL for a deployed SynthID detector.
                      Empty string returns a documented UNAVAILABLE result.
        hf_token:     HF bearer token for the endpoint.
        """
        self._endpoint = endpoint_url.rstrip("/")
        self._token = hf_token

    async def classify(self, data: bytes, mime_type: str = "text/plain") -> BackendResult:
        if not self._endpoint:
            return BackendResult(
                backend=self.name,
                score=0.0,
                confidence=0.0,
                attribution=SYNTHID_NOTE,
                error=(
                    "SynthID endpoint not configured. "
                    "Set synthid_endpoint to a deployed HF Inference Endpoint. "
                    "See docs/synthid-setup.md."
                ),
            )
        text = data.decode("utf-8", errors="replace")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                headers = {"Content-Type": "application/json"}
                if self._token:
                    headers["Authorization"] = f"Bearer {self._token}"
                resp = await client.post(
                    self._endpoint,
                    headers=headers,
                    json={"inputs": text},
                )
                resp.raise_for_status()
                result = resp.json()
                detected = result.get("watermark_detected", False)
                score = float(result.get("score", 1.0 if detected else 0.0))
                return BackendResult(
                    backend=self.name,
                    score=round(score, 4),
                    confidence=0.9,
                    attribution=SYNTHID_NOTE,
                    raw=result,
                )
        except Exception as exc:
            return BackendResult(
                backend=self.name, score=0.0, confidence=0.0,
                attribution=SYNTHID_NOTE, error=str(exc),
            )
