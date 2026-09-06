"""FakeSpotter — backends/base.py
Abstract base class for all classifier backends.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class BackendResult:
    backend: str
    score: float          # 0.0 (real) to 1.0 (AI-generated)
    confidence: float     # 0.0 to 1.0
    attribution: str      # likely model/generator, "" if unknown
    raw: dict = field(default_factory=dict)
    error: str = ""

    @property
    def succeeded(self) -> bool:
        return not self.error


class ClassifierBackend(ABC):
    name: str
    modality: str  # "image", "audio", "text", "video"

    @abstractmethod
    async def classify(self, data: bytes, mime_type: str = "") -> BackendResult:
        """Classify media bytes. Returns BackendResult."""
        ...
