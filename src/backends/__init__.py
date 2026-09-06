"""FakeSpotter — backends package
Neural classifier backends for AI-generated content detection.
All backends are BYOK (user supplies API keys). Free tiers available for all.
"""
from .base import ClassifierBackend, BackendResult
from .ensemble import EnsembleResult, run_ensemble
from .hf_image import HFImageBackend
from .hf_audio import HFAudioBackend
from .hf_text import HFTextBackend
from .sightengine import SightengineImageBackend
from .synthid import SynthIDTextBackend

__all__ = [
    "ClassifierBackend", "BackendResult",
    "EnsembleResult", "run_ensemble",
    "HFImageBackend", "HFAudioBackend", "HFTextBackend",
    "SightengineImageBackend", "SynthIDTextBackend",
]
