#!/usr/bin/env python3
"""
FakeSpotter — scripts/health_check.py
Monthly classifier health check.

Compares each backend's current accuracy against the baselines in
docs/classifier_baselines.json using the corpus in tests/fixtures/corpus_manifest.json.

A backend is DEGRADED if its accuracy drops more than DEGRADATION_THRESHOLD points.
A backend is UNAVAILABLE if the API returns errors on all samples.

Usage:
    cd /path/to/fakespotter-mcp
    python scripts/health_check.py [--hf-token HF_TOKEN] [--se-user SE_USER] [--se-secret SE_SECRET]

Environment variables (alternative to CLI flags):
    FAKESPOTTER_HF_TOKEN
    FAKESPOTTER_SE_USER
    FAKESPOTTER_SE_SECRET

Exit codes:
    0 — all backends OK
    1 — one or more backends DEGRADED or UNAVAILABLE
    2 — corpus or baseline files missing / malformed
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import date
from enum import Enum
from pathlib import Path

import httpx

ROOT = Path(__file__).parent.parent
MANIFEST_PATH  = ROOT / "tests" / "fixtures" / "corpus_manifest.json"
BASELINES_PATH = ROOT / "docs" / "classifier_baselines.json"
REPORT_PATH    = ROOT / "docs" / "health_report.md"

DEGRADATION_THRESHOLD = 10  # percentage points


# ---------------------------------------------------------------------------
# Status types
# ---------------------------------------------------------------------------

class BackendStatus(str, Enum):
    OK          = "OK"
    DEGRADED    = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED     = "SKIPPED"       # no API key provided


@dataclass
class BackendHealth:
    name:       str
    status:     BackendStatus
    accuracy:   float | None = None   # measured this run
    baseline:   float | None = None   # from baselines.json
    delta:      float | None = None   # current - baseline
    samples_ok: int = 0
    samples_total: int = 0
    errors:     list[str] = field(default_factory=list)
    notes:      str = ""


# ---------------------------------------------------------------------------
# Sample download
# ---------------------------------------------------------------------------

async def download_sample(url: str, client: httpx.AsyncClient) -> tuple[bytes, str]:
    """Download a corpus sample. Returns (bytes, detected_mime)."""
    resp = await client.get(url)
    resp.raise_for_status()
    data = resp.content
    ct   = resp.headers.get("content-type", "application/octet-stream").split(";")[0].strip()
    return data, ct


# ---------------------------------------------------------------------------
# Backend checks
# ---------------------------------------------------------------------------

async def check_hf_image(hf_token: str, manifest: dict) -> BackendHealth:
    health = BackendHealth(name="hf_image_ensemble", status=BackendStatus.UNAVAILABLE)
    samples = manifest["image"]["ai_generated"] + manifest["image"]["human"]
    health.samples_total = len(samples)

    HF_MODELS = [
        ("prithivMLmods/deepfake-detector-model-v1", "fake",  0.6),
        ("dima806/deepfake_vs_real_image_detection",  "Fake",  0.4),
    ]

    correct = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for sample in samples:
            try:
                data, mime = await download_sample(sample["url"], client)
                scores = []
                for model_id, fake_label, weight in HF_MODELS:
                    try:
                        resp = await client.post(
                            f"https://api-inference.huggingface.co/models/{model_id}",
                            headers={"Authorization": f"Bearer {hf_token}", "Content-Type": mime},
                            content=data,
                        )
                        resp.raise_for_status()
                        classes = resp.json()
                        fake_score = next((c["score"] for c in classes
                                           if fake_label.lower() in c["label"].lower()), 0.0)
                        scores.append((fake_score, weight))
                    except Exception as e:
                        health.errors.append(f"{model_id}: {e}")

                if scores:
                    total_w = sum(w for _, w in scores)
                    ensemble = sum(s * w for s, w in scores) / total_w
                    predicted = "ai_generated" if ensemble >= 0.5 else "human"
                    if predicted == sample["expected_label"]:
                        correct += 1
                    health.samples_ok += 1
            except Exception as e:
                health.errors.append(f"{sample['id']}: {e}")

    if health.samples_ok == 0:
        health.status = BackendStatus.UNAVAILABLE
    else:
        health.accuracy = (correct / health.samples_ok) * 100
        return _apply_baseline(health)
    return health


async def check_hf_text(hf_token: str, manifest: dict) -> BackendHealth:
    health = BackendHealth(name="hf_text_ensemble", status=BackendStatus.UNAVAILABLE)
    samples = manifest["text"]["ai_generated"] + manifest["text"]["human"]
    health.samples_total = len(samples)

    HF_TEXT_MODELS = [
        ("Hello-SimpleAI/chatgpt-detector-roberta",       "ChatGPT", 0.6),
        ("openai-community/roberta-base-openai-detector",  "Fake",    0.4),
    ]

    correct = 0
    async with httpx.AsyncClient(timeout=30) as client:
        for sample in samples:
            text = sample["content"]
            scores = []
            try:
                for model_id, ai_label, weight in HF_TEXT_MODELS:
                    try:
                        resp = await client.post(
                            f"https://api-inference.huggingface.co/models/{model_id}",
                            headers={"Authorization": f"Bearer {hf_token}"},
                            json={"inputs": text},
                        )
                        resp.raise_for_status()
                        raw = resp.json()
                        classes = raw[0] if isinstance(raw, list) else raw
                        ai_score = next((c["score"] for c in classes
                                          if ai_label.lower() in c["label"].lower()), 0.0)
                        scores.append((ai_score, weight))
                    except Exception as e:
                        health.errors.append(f"{model_id}: {e}")

                if scores:
                    total_w = sum(w for _, w in scores)
                    ensemble = sum(s * w for s, w in scores) / total_w
                    predicted = "ai_generated" if ensemble >= 0.5 else "human"
                    if predicted == sample["expected_label"]:
                        correct += 1
                    health.samples_ok += 1
            except Exception as e:
                health.errors.append(f"{sample['id']}: {e}")

    if health.samples_ok == 0:
        health.status = BackendStatus.UNAVAILABLE
    else:
        health.accuracy = (correct / health.samples_ok) * 100
        return _apply_baseline(health)
    return health


async def check_connectivity(backend_name: str, url: str, hf_token: str = "") -> bool:
    """Quick liveness check — just verify the endpoint responds."""
    try:
        headers = {}
        if hf_token:
            headers["Authorization"] = f"Bearer {hf_token}"
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            return resp.status_code < 500
    except Exception:
        return False


def _apply_baseline(health: BackendHealth) -> BackendHealth:
    try:
        baselines = json.loads(BASELINES_PATH.read_text())
        bl = baselines["baselines"].get(health.name, {})
        health.baseline = bl.get("accuracy_pct")
        threshold = baselines["_meta"].get("degradation_threshold_points", DEGRADATION_THRESHOLD)
        if health.baseline is not None and health.accuracy is not None:
            health.delta = health.accuracy - health.baseline
            if health.delta < -threshold:
                health.status = BackendStatus.DEGRADED
                health.notes = f"Dropped {abs(health.delta):.1f} pts below baseline"
            else:
                health.status = BackendStatus.OK
        else:
            health.status = BackendStatus.OK
    except Exception as e:
        health.notes = f"Could not load baseline: {e}"
        health.status = BackendStatus.OK
    return health


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def render_report(results: list[BackendHealth]) -> str:
    today = date.today().isoformat()
    lines = [
        "# FakeSpotter — Classifier Health Report",
        "",
        f"*Generated: {today}*",
        "",
        "| Backend | Status | Accuracy | Baseline | Delta | Samples |",
        "|---------|--------|----------|----------|-------|---------|",
    ]
    for r in results:
        acc  = f"{r.accuracy:.1f}%" if r.accuracy is not None else "—"
        bl   = f"{r.baseline:.1f}%" if r.baseline is not None else "—"
        dlt  = f"{r.delta:+.1f}%" if r.delta is not None else "—"
        icon = {"OK": "✅", "DEGRADED": "🔴", "UNAVAILABLE": "⚠️", "SKIPPED": "⏭️"}[r.status]
        lines.append(
            f"| `{r.name}` | {icon} {r.status} | {acc} | {bl} | {dlt} "
            f"| {r.samples_ok}/{r.samples_total} |"
        )

    degraded = [r for r in results if r.status == BackendStatus.DEGRADED]
    unavail  = [r for r in results if r.status == BackendStatus.UNAVAILABLE]

    if degraded or unavail:
        lines += ["", "## Action required", ""]
        for r in degraded:
            lines.append(f"- **{r.name}** DEGRADED: {r.notes}")
            if r.errors:
                lines.append(f"  Errors: {'; '.join(r.errors[:3])}")
        for r in unavail:
            lines.append(f"- **{r.name}** UNAVAILABLE")
            if r.errors:
                lines.append(f"  Errors: {'; '.join(r.errors[:3])}")
        lines += [
            "",
            "### Recommended actions",
            "1. Check if the HF model still exists and the API key is valid",
            "2. Run `eval_deterministic.py` to measure current accuracy on the deterministic tools",
            "3. If the model has been superseded, update `hf_music.py` / `hf_audio.py` / `hf_image.py`",
            "4. Update `docs/classifier_baselines.json` after any backend replacement",
            "5. Update `tests/fixtures/corpus_manifest.json` to include samples for new generators",
        ]
    else:
        lines += ["", "## All backends healthy ✅"]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    parser = argparse.ArgumentParser(description="FakeSpotter classifier health check")
    parser.add_argument("--hf-token",  default=os.getenv("FAKESPOTTER_HF_TOKEN", ""))
    parser.add_argument("--se-user",   default=os.getenv("FAKESPOTTER_SE_USER", ""))
    parser.add_argument("--se-secret", default=os.getenv("FAKESPOTTER_SE_SECRET", ""))
    args = parser.parse_args()

    if not MANIFEST_PATH.exists():
        print(f"ERROR: corpus manifest not found at {MANIFEST_PATH}", file=sys.stderr)
        return 2
    if not BASELINES_PATH.exists():
        print(f"ERROR: baselines not found at {BASELINES_PATH}", file=sys.stderr)
        return 2

    manifest = json.loads(MANIFEST_PATH.read_text())
    results: list[BackendHealth] = []

    print("FakeSpotter — Classifier Health Check")
    print("=" * 50)

    # HF image
    if args.hf_token:
        print("[1/3] Checking hf_image_ensemble...")
        r = await check_hf_image(args.hf_token, manifest)
        results.append(r)
        print(f"      {r.status} — accuracy={r.accuracy:.1f}% baseline={r.baseline}% delta={r.delta:+.1f}%"
              if r.accuracy is not None else f"      {r.status}")
    else:
        results.append(BackendHealth(
            name="hf_image_ensemble", status=BackendStatus.SKIPPED,
            notes="No HF token provided (FAKESPOTTER_HF_TOKEN)"
        ))
        print("[1/3] hf_image_ensemble — SKIPPED (no HF token)")

    # HF text
    if args.hf_token:
        print("[2/3] Checking hf_text_ensemble...")
        r = await check_hf_text(args.hf_token, manifest)
        results.append(r)
        print(f"      {r.status} — accuracy={r.accuracy:.1f}%" if r.accuracy is not None else f"      {r.status}")
    else:
        results.append(BackendHealth(
            name="hf_text_ensemble", status=BackendStatus.SKIPPED,
            notes="No HF token provided"
        ))
        print("[2/3] hf_text_ensemble — SKIPPED")

    # HF model liveness (connectivity only — no audio corpus yet)
    print("[3/3] Checking HF model availability (liveness)...")
    music_live = await check_connectivity(
        "hf_music",
        "https://api-inference.huggingface.co/models/AI-Music-Detection/ai_music_detection_large_60s",
        args.hf_token,
    )
    audio_live = await check_connectivity(
        "hf_audio_ensemble",
        "https://api-inference.huggingface.co/models/koyelog/deepfake-voice-detector-sota",
        args.hf_token,
    )
    for name, live in [("hf_music", music_live), ("hf_audio_ensemble", audio_live)]:
        status = BackendStatus.OK if live else BackendStatus.UNAVAILABLE
        r = BackendHealth(name=name, status=status, notes="Liveness check only — no audio corpus yet")
        results.append(r)
        print(f"      {name}: {status}")

    # Render report
    report = render_report(results)
    REPORT_PATH.write_text(report)
    print(f"\nReport written to {REPORT_PATH}")
    print("\n" + report)

    degraded = [r for r in results if r.status in (BackendStatus.DEGRADED, BackendStatus.UNAVAILABLE)]
    return 1 if degraded else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
