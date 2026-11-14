"""
Shared pytest setup for the real-library regression suite (tests/).

These tests run in their own process (pytest), separate from
scripts/regression_test.py, which stubs PIL/fitz/cv2/pyhanko/... with
MagicMock at import time. Here every library is the real one; the guard
below fails loudly if a stub ever leaks in.

Network: all HTTP downloads made by the tools go through httpx, which is
redirected to an in-process httpx.MockTransport (see the ``web`` fixture).
Nothing leaves the machine and no API keys are needed.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))

os.environ.setdefault("FAKESPOTTER_TMP", "/tmp/fakespotter")
Path(os.environ["FAKESPOTTER_TMP"]).mkdir(parents=True, exist_ok=True)

from tests.offline_http import offline_http  # noqa: E402

_REAL_LIBS = ("PIL", "fitz", "pymupdf", "cv2", "pyhanko", "imagehash")


def pytest_sessionstart(session):  # noqa: ARG001
    for name in _REAL_LIBS:
        mod = sys.modules.get(name)
        if isinstance(mod, MagicMock):
            raise pytest.UsageError(
                f"{name} is a MagicMock stub: run tests/ in its own process, "
                "never together with scripts/regression_test.py"
            )


@pytest.fixture(scope="session", autouse=True)
def _real_libraries_loaded():
    """Import the heavy libraries for real and make sure none is a stub."""
    import importlib

    for name in ("PIL.Image", "pymupdf", "cv2", "pyhanko", "imagehash", "numpy"):
        mod = importlib.import_module(name)
        assert not isinstance(mod, MagicMock), f"{name} is stubbed"
        assert isinstance(mod, types.ModuleType), f"{name} is not a real module"


@pytest.fixture
def web():
    """Serve fixture bytes to every ``httpx.AsyncClient`` the tools create."""
    with offline_http() as fake:
        yield fake
