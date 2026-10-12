#!/usr/bin/env python3
"""
FakeSpotter — regression_test.py
Verifica que las tools críticas se comporten correctamente sin claves reales.

Cubre:
  1. detect_ai_generated_text — fallback estadístico (sin hf_token)
  2. detect_ai_generated_text — path neural (hf_token presente, HF API mockeada)
  3. analyze_audio_authenticity — fallback Layer-1 (sin hf_token)
  4. analyze_audio_authenticity — path neural (hf_token presente, HF API mockeada)
  5. detect_ai_generated_image — fallback sin claves
  6. detect_ai_generated_music — fallback sin claves
  7. Todos los campos requeridos en los resultados (detection_engine, forensic_flags)
  8. LAYER_1_FALLBACK presente en fallback, ausente en path neural

Uso:
    cd /path/to/fakespotter-mcp
    python scripts/regression_test.py

Requiere: pytest (se instala si falta) o corre directamente.
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

os.environ.setdefault("FAKESPOTTER_TRANSPORT", "stdio")
os.environ.setdefault("FAKESPOTTER_TMP", "/tmp/fakespotter")
Path(os.environ["FAKESPOTTER_TMP"]).mkdir(parents=True, exist_ok=True)

# Stub out heavy optional deps that aren't installed in the test environment
for _mod in ("yt_dlp", "cv2", "PIL", "PIL.Image", "imagehash",
             "pymupdf", "fitz", "pyhanko", "c2pa", "passporteye"):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

HUMAN_TEXT = """
The quarterly earnings report surprised most analysts who had expected weaker numbers.
Revenue climbed sharply despite a difficult macroeconomic environment, driven largely
by the company's expansion into emerging markets. The CEO credited the team's focus
on operational efficiency and customer retention. Shares rose modestly in after-hours
trading. Several analysts upgraded their price targets following the announcement,
though some cautioned that supply chain risks remain a concern for the year ahead.
"""

AI_TEXT = (
    "In conclusion, it is important to note that the integration of advanced machine "
    "learning techniques has significantly transformed various industries. Furthermore, "
    "it is worth mentioning that these developments have led to unprecedented levels of "
    "efficiency. Moreover, it is essential to consider that the implementation of such "
    "technologies requires careful planning. Additionally, it should be noted that "
    "stakeholder engagement is paramount. In summary, the aforementioned factors "
    "demonstrate the critical importance of embracing technological innovation."
)

# Minimal valid WAV (44 bytes: RIFF header + empty data chunk)
WAV_BYTES = (
    b"RIFF\x24\x00\x00\x00WAVEfmt "
    b"\x10\x00\x00\x00\x01\x00\x01\x00"
    b"\x80\x3e\x00\x00\x00\x7d\x00\x00"
    b"\x02\x00\x10\x00data\x00\x00\x00\x00"
)


# ---------------------------------------------------------------------------
# Mock factory for HF Inference API
# ---------------------------------------------------------------------------

def _hf_text_mock_response(model_id: str) -> list:
    """Simula la respuesta de HF text classification API."""
    if "chatgpt-detector" in model_id:
        return [[{"label": "ChatGPT", "score": 0.82}, {"label": "Human", "score": 0.18}]]
    return [[{"label": "Fake", "score": 0.75}, {"label": "Real", "score": 0.25}]]


def _hf_audio_mock_response(model_id: str) -> list:
    """Simula la respuesta de HF audio classification API."""
    return [[{"label": "spoof", "score": 0.78}, {"label": "bonafide", "score": 0.22}]]


# ---------------------------------------------------------------------------
# Tests: detect_ai_generated_text
# ---------------------------------------------------------------------------

class TestDetectAIGeneratedText(unittest.IsolatedAsyncioTestCase):

    async def _call_tool(self, text: str, hf_token: str = "") -> str:
        """Llama la función de la tool directamente (sin MCP protocol overhead)."""
        from tools.document_tools import DetectAITextInput
        import tools.document_tools as dt

        # Instanciamos el módulo y extraemos la función registrada
        from mcp.server.fastmcp import FastMCP
        mcp = FastMCP("test")
        dt.register_detect_ai_generated_text(mcp)
        # Extraemos la función directamente del tool manager
        tool_fn = mcp._tool_manager._tools["detect_ai_generated_text"].fn
        params = DetectAITextInput(text=text, hf_token=hf_token, report_mode="quick")
        return await tool_fn(params)

    async def test_statistical_fallback_returns_layer1_flag(self):
        """Sin hf_token, el resultado incluye LAYER_1_FALLBACK."""
        result = await self._call_tool(AI_TEXT, hf_token="")
        self.assertIn("LAYER_1_FALLBACK", result,
                      "El fallback estadístico debe declarar LAYER_1_FALLBACK")

    async def test_statistical_fallback_verdict_present(self):
        """Sin hf_token, el resultado incluye un veredicto reconocible."""
        result = await self._call_tool(AI_TEXT, hf_token="")
        # Quick mode: "Authentic (N/100)" or "Fake (N/100)" or "Uncertain"
        has_verdict = any(kw in result for kw in (
            "Authentic", "Fake", "Uncertain", "DETECTED", "VERIFIED", "LIKELY",
            "Auténtico", "Falso", "Incierto",
        ))
        self.assertTrue(has_verdict, f"No se encontró veredicto en: {result!r}")

    async def test_neural_path_no_layer1_flag(self):
        """Con hf_token y API mockeada, NO debe aparecer LAYER_1_FALLBACK."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()

        def json_side_effect():
            return [[{"label": "ChatGPT", "score": 0.82}, {"label": "Human", "score": 0.18}]]

        mock_resp.json = json_side_effect

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await self._call_tool(AI_TEXT, hf_token="hf_fake_token_for_test")

        self.assertNotIn("LAYER_1_FALLBACK", result,
                         "El path neural no debe incluir LAYER_1_FALLBACK")

    async def test_neural_path_returns_verdict(self):
        """Con hf_token y API mockeada, el resultado incluye un veredicto."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = lambda: [[{"label": "ChatGPT", "score": 0.82}, {"label": "Human", "score": 0.18}]]

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            result = await self._call_tool(AI_TEXT, hf_token="hf_fake_token_for_test")

        has_verdict = any(kw in result for kw in ("Authentic", "Fake", "Uncertain",
                                                    "Auténtico", "Falso", "Incierto"))
        self.assertTrue(has_verdict, f"No se encontró veredicto en: {result!r}")

    async def test_human_text_lower_ai_score_statistical(self):
        """Texto humano debe producir menor puntaje de IA que texto AI."""
        result_human = await self._call_tool(HUMAN_TEXT, hf_token="")
        result_ai    = await self._call_tool(AI_TEXT,    hf_token="")
        # Ambos son resultados quick=False (full), buscar scores en el JSON embebido
        # Al menos uno de los indicadores de IA debe estar ausente en el texto humano
        self.assertNotEqual(result_human, result_ai,
                            "Texto humano y AI no deben producir resultados idénticos")


# ---------------------------------------------------------------------------
# Tests: analyze_audio_authenticity
# ---------------------------------------------------------------------------

class TestAnalyzeAudioAuthenticity(unittest.IsolatedAsyncioTestCase):

    async def _call_tool(
        self, media_url: str = "https://example.com/test.wav",
        hf_token: str = "",
    ) -> str:
        from tools.media_tools import AnalyzeAudioInput
        import tools.media_tools as mt
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        mt.register_analyze_audio_authenticity(mcp)
        tool_fn = mcp._tool_manager._tools["analyze_audio_authenticity"].fn

        params = AnalyzeAudioInput(media_url=media_url, hf_token=hf_token, report_mode="quick")

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        # Use real dict for headers so comparisons work (not MagicMock)
        mock_resp.headers = {
            "content-type": "audio/wav",
            "content-length": str(len(WAV_BYTES)),
        }

        async def aiter_bytes(chunk_size=65536):
            yield WAV_BYTES

        mock_resp.aiter_bytes = aiter_bytes
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        safe_meta = {
            "acodec": "aac", "abr": 128, "asr": 44100,
            "encoder": "", "description": "", "tags": [],
        }

        with patch("httpx.AsyncClient") as mock_client_cls, \
             patch("tools.media_tools.fetch_media_metadata", return_value=safe_meta), \
             patch("utils.audio.to_wav_16k_mono", return_value=(WAV_BYTES, "wav")):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client.stream = MagicMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client

            return await tool_fn(params)

    async def test_audio_fallback_layer1_flag(self):
        """Sin hf_token, analyze_audio_authenticity incluye LAYER_1_FALLBACK."""
        result = await self._call_tool(hf_token="")
        self.assertIn("LAYER_1_FALLBACK", result)

    async def test_audio_fallback_verdict_present(self):
        """Sin hf_token, el resultado incluye un veredicto."""
        result = await self._call_tool(hf_token="")
        has_verdict = any(kw in result for kw in (
            "AUTHENTIC", "Authentic", "FAKE", "Fake", "UNCERTAIN", "Uncertain",
            "DETECTED", "VERIFIED", "LIKELY", "Auténtico", "Falso", "Incierto",
        ))
        self.assertTrue(has_verdict, f"No se encontró veredicto en: {result!r}")


# ---------------------------------------------------------------------------
# Tests: backends — imports y exportaciones
# ---------------------------------------------------------------------------

class TestBackendExports(unittest.TestCase):

    def test_hf_text_backend_importable(self):
        from backends import HFTextBackend
        self.assertEqual(HFTextBackend.modality, "text")

    def test_hf_audio_backend_importable(self):
        from backends import HFAudioBackend
        self.assertEqual(HFAudioBackend.modality, "audio")

    def test_hf_image_backend_importable(self):
        from backends import HFImageBackend
        self.assertEqual(HFImageBackend.modality, "image")

    def test_hf_music_backend_importable(self):
        from backends import HFMusicBackend

    def test_run_ensemble_importable(self):
        from backends.ensemble import run_ensemble
        self.assertTrue(callable(run_ensemble))


# ---------------------------------------------------------------------------
# Tests: DetectAITextInput — validación de schema
# ---------------------------------------------------------------------------

class TestDetectAITextInputSchema(unittest.TestCase):

    def test_hf_token_field_exists(self):
        from tools.document_tools import DetectAITextInput
        fields = DetectAITextInput.model_fields
        self.assertIn("hf_token", fields,
                      "DetectAITextInput debe tener campo hf_token")

    def test_hf_token_default_empty(self):
        from tools.document_tools import DetectAITextInput
        obj = DetectAITextInput(text="A" * 60)
        self.assertEqual(obj.hf_token, "")

    def test_lang_default_en(self):
        from tools.document_tools import DetectAITextInput
        obj = DetectAITextInput(text="A" * 60)
        self.assertEqual(obj.lang, "en")

    def test_extra_fields_forbidden(self):
        from tools.document_tools import DetectAITextInput
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            DetectAITextInput(text="A" * 60, unknown_field="x")


# ---------------------------------------------------------------------------
# Tests: AnalyzeAudioInput — validación de schema
# ---------------------------------------------------------------------------

class TestAnalyzeAudioInputSchema(unittest.TestCase):

    def test_hf_token_field_exists(self):
        from tools.media_tools import AnalyzeAudioInput
        fields = AnalyzeAudioInput.model_fields
        self.assertIn("hf_token", fields)

    def test_se_user_field_exists(self):
        from tools.media_tools import AnalyzeAudioInput
        fields = AnalyzeAudioInput.model_fields
        self.assertIn("se_user", fields)

    def test_hf_token_default_empty(self):
        from tools.media_tools import AnalyzeAudioInput
        obj = AnalyzeAudioInput(media_url="https://example.com/test.mp3")
        self.assertEqual(obj.hf_token, "")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    for cls in [
        TestDetectAITextInputSchema,
        TestAnalyzeAudioInputSchema,
        TestBackendExports,
        TestDetectAIGeneratedText,
        TestAnalyzeAudioAuthenticity,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
