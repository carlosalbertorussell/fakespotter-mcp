"""
FakeSpotter — Forensic report generator.
Produces cryptographically authenticated certificates using HMAC-SHA256.

Per-user signing: each subscriber provides their own FAKESPOTTER_SECRET,
injected by MCPize at request time. This ensures chain of custody —
certificates are signed with the user's own key, not a shared platform key.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
from typing import Any


VERSION = "1.0.0"
_DEFAULT_SECRET = "fakespotter-dev-secret"


def _get_secret(user_secret: str | None = None) -> bytes:
    """
    Resolve the signing secret in priority order:
    1. Explicitly passed user_secret (from per-user MCPize credential)
    2. FAKESPOTTER_SECRET environment variable (self-hosted / shared mode)
    3. Development fallback (never use in production)
    """
    secret = (
        user_secret
        or os.environ.get("FAKESPOTTER_SECRET")
        or _DEFAULT_SECRET
    )
    return secret.encode("utf-8")


class ForensicReporter:
    """Generates signed forensic certificates."""

    @staticmethod
    def generate_report(
        tool_name: str,
        findings: dict[str, Any],
        lang: str = "en",
        user_secret: str | None = None,
    ) -> dict[str, Any]:
        """
        Build a forensic report dict with:
        - ISO-8601 UTC timestamp
        - HMAC-SHA256 signature using the user's own signing key
        - Structured findings payload

        Args:
            tool_name: Name of the forensic tool that produced the findings
            findings: Dict of forensic findings
            lang: Report language ('en' or 'es')
            user_secret: Per-user signing key (injected by MCPize per subscriber).
                         If None, falls back to FAKESPOTTER_SECRET env var.
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        payload = {
            "tool":      tool_name,
            "findings":  findings,
            "timestamp": timestamp,
            "version":   VERSION,
            "lang":      lang,
        }

        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        secret_bytes = _get_secret(user_secret)

        signature = hmac.new(
            secret_bytes,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        integrity_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        return {
            "header":    "FakeSpotter Forensic Certificate",
            "version":   VERSION,
            "metadata": {
                "timestamp":      timestamp,
                "tool":           tool_name,
                "lang":           lang,
                "integrity_hash": integrity_hash,
                "hmac_signature": signature,
                "signing_mode":   "per_user" if user_secret else "shared",
            },
            "data": payload,
        }

    @staticmethod
    def format_certificate(report: dict[str, Any], findings: dict[str, Any]) -> str:
        """Render a human-readable Forensic Certificate string."""
        meta    = report["metadata"]
        verdict = findings.get("verdict", "UNKNOWN")
        score   = findings.get("trust_score", findings.get("confidence_score", "N/A"))
        flags   = findings.get("forensic_flags", [])
        flag_str = "\n".join(f"  ⚠  {f}" for f in flags) if flags else "  ✓  None detected"
        signing  = meta.get("signing_mode", "shared")

        return (
            f"{'─' * 56}\n"
            f"  FAKESPOTTER FORENSIC CERTIFICATE  v{report['version']}\n"
            f"{'─' * 56}\n"
            f"  Tool      : {meta['tool']}\n"
            f"  Date/Time : {meta['timestamp']}\n"
            f"  Report ID : {meta['integrity_hash'][:24]}…\n"
            f"  Signing   : {signing.upper()}\n"
            f"{'─' * 56}\n"
            f"  VERDICT   : {verdict}\n"
            f"  CONFIDENCE: {score}/100\n"
            f"{'─' * 56}\n"
            f"  FORENSIC FLAGS:\n{flag_str}\n"
            f"{'─' * 56}\n"
            f"  SHA-256 INTEGRITY:\n"
            f"  {meta['integrity_hash']}\n"
            f"  HMAC-SHA256 SIGNATURE:\n"
            f"  {meta['hmac_signature']}\n"
            f"{'─' * 56}\n"
        )
