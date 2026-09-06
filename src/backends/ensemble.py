"""FakeSpotter — backends/ensemble.py
Aggregates results from N backends into a single weighted verdict.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Sequence
from .base import ClassifierBackend, BackendResult


@dataclass
class EnsembleResult:
    score: float
    verdict: str
    confidence: float
    attribution: str
    backends_used: list[str]
    backend_scores: dict[str, float]
    backends_failed: list[str]

    def to_findings(self) -> dict:
        return {
            "ensemble_score": self.score,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "attribution": self.attribution or "unknown",
            "backends_used": self.backends_used,
            "backend_scores": self.backend_scores,
            "backends_failed": self.backends_failed,
        }


async def run_ensemble(
    backends: Sequence[ClassifierBackend],
    data: bytes,
    mime_type: str = "image/jpeg",
    threshold_fake: float = 0.65,
    threshold_uncertain: float = 0.35,
) -> EnsembleResult:
    """Run all backends concurrently and aggregate by confidence weight."""
    tasks = [b.classify(data, mime_type) for b in backends]
    raw: list[BackendResult] = await asyncio.gather(*tasks, return_exceptions=False)

    succeeded = [r for r in raw if r.succeeded]
    failed    = [r for r in raw if not r.succeeded]

    if not succeeded:
        return EnsembleResult(
            score=0.0, verdict="DETECTION_UNAVAILABLE",
            confidence=0.0, attribution="",
            backends_used=[], backend_scores={},
            backends_failed=[r.backend for r in failed],
        )

    total_conf = sum(r.confidence for r in succeeded) or 1.0
    score = sum(r.score * r.confidence for r in succeeded) / total_conf
    confidence = total_conf / max(len(backends), 1)
    attribution = next((r.attribution for r in succeeded if r.attribution), "")

    if score >= threshold_fake:
        verdict = "LIKELY_AI_GENERATED"
    elif score >= threshold_uncertain:
        verdict = "UNCERTAIN"
    else:
        verdict = "LIKELY_AUTHENTIC"

    return EnsembleResult(
        score=round(score, 4),
        verdict=verdict,
        confidence=round(confidence, 4),
        attribution=attribution,
        backends_used=[r.backend for r in succeeded],
        backend_scores={r.backend: round(r.score, 4) for r in succeeded},
        backends_failed=[r.backend for r in failed],
    )
