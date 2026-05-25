"""
FakeSpotter — Internationalisation manager.
Loads locale JSON files from src/locales/ at startup.
Supports dot-notation keys for nested structures.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class I18nManager:
    def __init__(self, default_lang: str = "en") -> None:
        self.default_lang = default_lang
        self.translations: dict[str, dict[str, Any]] = {}
        self._load_locales()

    def _load_locales(self) -> None:
        base_dir = Path(__file__).parent.parent / "locales"

        if not base_dir.exists():
            logger.warning("Locales directory not found: %s — i18n disabled", base_dir)
            return

        for file_path in sorted(base_dir.glob("*.json")):
            try:
                with open(file_path, encoding="utf-8") as fh:
                    self.translations[file_path.stem] = json.load(fh)
                logger.debug("Loaded locale: %s", file_path.stem)
            except (json.JSONDecodeError, OSError) as exc:
                logger.error("Failed to load locale %s: %s", file_path.name, exc)

    def t(self, key: str, lang: str | None = None) -> str:
        """
        Translate *key* into *lang* (or default_lang).
        Supports dot-notation: t("errors.not_found", "es")
        Falls back to default_lang, then returns [key] sentinel.
        """
        target = lang if lang in self.translations else self.default_lang
        locale_data = self.translations.get(target, {})

        # Dot-notation traversal
        parts = key.split(".")
        node: Any = locale_data
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                node = None
                break

        if node is not None:
            return str(node)

        # Try default lang if target failed
        if target != self.default_lang:
            return self.t(key, self.default_lang)

        return f"[{key}]"

    @property
    def available_languages(self) -> list[str]:
        return sorted(self.translations.keys())


# Module-level singleton
i18n = I18nManager()
