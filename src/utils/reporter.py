"""
FakeSpotter — Forensic report generator.
Produces cryptographically authenticated certificates using HMAC-SHA256.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
from typing import Any


VERSION = "1.0.0"
_SECRET = os.environ.get("FAKESPOTTER_SECRET", "fakespotter-dev-secret").encode()


class ForensicReporter:
    """Generates signed forensic certificates."""

    @staticmethod
    def generate_report(
        tool_name: str,
        findings: dict[str, Any],
        lang: str = "en",
    ) -> dict[str, Any]:
        """
        Build a forensic report dict with:
        - ISO-8601 UTC timestamp
        - HMAC-SHA256 signature (prevents post-hoc tampering)
        - Structured findings payload
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        payload = {
            "tool":      tool_name,
            "findings":  findings,
            "timestamp": timestamp,
            "version":   VERSION,
            "lang":      lang,
        }

        # Canonical JSON → deterministic serialisation
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)

        # HMAC-SHA256: unlike a bare digest, this cannot be forged without the key
        signature = hmac.new(
            _SECRET,
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Also include a plain SHA-256 of the payload for public verification display
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
            },
            "data": payload,
        }

    @staticmethod
    def format_certificate(report: dict[str, Any], findings: dict[str, Any]) -> str:
        """
        Render a human-readable Forensic Certificate string.
        Used for the full_report mode response.
        """
        meta = report["metadata"]
        verdict  = findings.get("verdict", "UNKNOWN")
        score    = findings.get("trust_score", findings.get("confidence_score", "N/A"))
        flags    = findings.get("forensic_flags", [])
        flag_str = "\n".join(f"  ⚠  {f}" for f in flags) if flags else "  ✓  None detected"

        return (
            f"{'─' * 56}\n"
            f"  FAKESPOTTER FORENSIC CERTIFICATE  v{report['version']}\n"
            f"{'─' * 56}\n"
            f"  Tool      : {meta['tool']}\n"
            f"  Date/Time : {meta['timestamp']}\n"
            f"  Report ID : {meta['integrity_hash'][:24]}…\n"
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
