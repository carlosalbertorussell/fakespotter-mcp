"""FakeSpotter — backends package
Neural classifier backends for AI-generated content detection.
"""
from .base import ClassifierBackend, BackendResult
from .ensemble import EnsembleResult, run_ensemble
from .hf_image import HFImageBackend
from .sightengine import SightengineImageBackend

__all__ = [
    "ClassifierBackend", "BackendResult",
    "EnsembleResult", "run_ensemble",
    "HFImageBackend", "SightengineImageBackend",
]
