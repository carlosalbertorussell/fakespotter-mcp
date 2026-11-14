#!/usr/bin/env python3
"""
FakeSpotter -- eval_deterministic.py
Evaluates FP/FN rates for the 4 deterministic Invoice Guard tools.

Every verdict comes from the REAL tool in src/tools/, called through the
public MCP client API (tests/mcp_client.py), so this report cannot drift
from the code it measures. verify_document_integrity, analyze_file_metadata
and check_email_headers are evaluated offline (fixture bytes are served via
httpx.MockTransport); analyze_url_reputation is evaluated live (DNS + HTTP).

Usage:
    cd /path/to/fakespotter-mcp
    python scripts/eval_deterministic.py              # all 4 tools (needs network)
    python scripts/eval_deterministic.py --skip-live  # offline tools only; the
        analyze_url_reputation row is written as "not measured"

Run the live step only from a host with direct Internet access: behind an
egress proxy, unreachable domains come back as a proxy 502 (httpx.ProxyError)
and established sites can answer the proxy's own status codes, so the
numbers describe the proxy, not the tool.

Writes results to docs/accuracy.md
No running MCP server required.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(_ROOT))
os.environ.setdefault("FAKESPOTTER_TMP", "/tmp/fakespotter")
Path(os.environ["FAKESPOTTER_TMP"]).mkdir(parents=True, exist_ok=True)

from tests.fixtures.email_samples import CLEAN_HEADERS, SPOOFED_HEADERS  # noqa: E402
from tests.mcp_client import acall_tool  # noqa: E402
from tests.offline_http import offline_http  # noqa: E402

EVAL_HOST = "https://eval.fakespotter.test"


@dataclass
class EvalResult:
    tool: str
    corpus_size: int
    measured: bool = True
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    notes: str = ""

    @property
    def fp_rate(self) -> float:
        d = self.tn + self.fp
        return (self.fp / d * 100) if d else 0.0

    @property
    def fn_rate(self) -> float:
        d = self.tp + self.fn
        return (self.fn / d * 100) if d else 0.0

    @property
    def accuracy(self) -> float:
        t = self.tp + self.tn + self.fp + self.fn
        return ((self.tp + self.tn) / t * 100) if t else 0.0


TOOL_ERRORS: dict[str, list[str]] = {}


async def _verdict(tool: str, **params) -> str:
    """Run a real tool in full mode and return the certificate's VERDICT.

    A tool that answers with an error instead of a verdict is scored as a
    miss (FP for a clean sample, FN for a bad one) and the error is reported
    in the notes, rather than aborting the whole evaluation.
    """
    res = await acall_tool(tool, report_mode="full", **params)
    if res.verdict is None:
        TOOL_ERRORS.setdefault(tool, []).append(res.text.strip().splitlines()[0][:160])
        return "TOOL_ERROR"
    return res.verdict


def _error_note(tool: str) -> str:
    errors = TOOL_ERRORS.get(tool, [])
    if not errors:
        return ""
    return (f" Tool returned an error instead of a verdict on {len(errors)} sample(s), "
            f"scored as misses: `{errors[0]}`.")


# ---------------------------------------------------------------------------
# Tool 1: verify_document_integrity
# ---------------------------------------------------------------------------

async def eval_verify_document_integrity(n: int = 100) -> EvalResult:
    r = EvalResult("verify_document_integrity", corpus_size=n * 2)
    with offline_http() as web:
        for i in range(n):
            content = os.urandom(512 + i)
            sha256 = hashlib.sha256(content).hexdigest()
            tampered = bytearray(content)
            tampered[0] ^= 0xFF
            url = f"{EVAL_HOST}/doc_{i}.bin"

            web.serve(url, content)
            v = await _verdict("verify_document_integrity", file_url=url, expected_sha256=sha256)
            if v == "DOCUMENT_INTACT": r.tn += 1
            else: r.fp += 1

            web.serve(url, bytes(tampered))
            v = await _verdict("verify_document_integrity", file_url=url, expected_sha256=sha256)
            if v == "DOCUMENT_TAMPERED": r.tp += 1
            else: r.fn += 1
    r.notes = (
        "SHA-256 collision-resistant; 0% FP/FN by mathematical guarantee, "
        "not by empirical measurement. Verdicts produced by the real tool."
    )
    r.notes += _error_note("verify_document_integrity")
    return r


# ---------------------------------------------------------------------------
# Tool 2: analyze_file_metadata
# ---------------------------------------------------------------------------

MAGIC_HEADERS = {
    "JPEG": b"\xff\xd8\xff\xe0" + b"\x00" * 508,
    "PNG":  b"\x89PNG\r\n\x1a\n" + b"\x00" * 504,
    "GIF":  b"GIF89a" + b"\x00" * 506,
    "PDF":  b"%PDF-1.7\n" + b"\x00" * 503,
    "ZIP":  b"PK\x03\x04" + b"\x00" * 509,
}


async def eval_analyze_file_metadata() -> EvalResult:
    r = EvalResult("analyze_file_metadata", corpus_size=0)

    clean = [
        (MAGIC_HEADERS["JPEG"], "jpg"),
        (MAGIC_HEADERS["JPEG"], "jpeg"),
        (MAGIC_HEADERS["PNG"],  "png"),
        (MAGIC_HEADERS["PDF"],  "pdf"),
        (MAGIC_HEADERS["ZIP"],  "zip"),
        (MAGIC_HEADERS["GIF"],  "gif"),
        (b"plain text without magic", "txt"),
        (b"another plain text file",  "csv"),
        (b"\x00" * 4096,             "bin"),   # zero entropy
    ]
    flagged = [
        (MAGIC_HEADERS["JPEG"], "pdf"),
        (MAGIC_HEADERS["PNG"],  "jpg"),
        (MAGIC_HEADERS["PDF"],  "zip"),
        (MAGIC_HEADERS["ZIP"],  "jpg"),
        (MAGIC_HEADERS["GIF"],  "pdf"),
        (os.urandom(4096),      "bin"),   # high entropy
    ]

    with offline_http() as web:
        for i, (content, ext) in enumerate(clean + flagged):
            expect_flagged = i >= len(clean)
            url = web.serve(f"{EVAL_HOST}/sample_{i}.{ext}", content)
            r.corpus_size += 1
            v = await _verdict("analyze_file_metadata", file_url=url)
            if expect_flagged:
                if v != "FILE_CLEAN": r.tp += 1
                else: r.fn += 1
            else:
                if v == "FILE_CLEAN": r.tn += 1
                else: r.fp += 1

    r.notes = (
        "Magic-byte mismatch detection is deterministic (+40 pts -> REVIEW_RECOMMENDED). "
        "Entropy signal: +25 pts (fixed in S10) — high-entropy file now reaches REVIEW_RECOMMENDED threshold. "
        "FN rate: 0% after fix (was 16.7%)."
    )
    r.notes += _error_note("analyze_file_metadata")
    return r


# ---------------------------------------------------------------------------
# Tool 3: check_email_headers
# ---------------------------------------------------------------------------

async def eval_check_email_headers() -> EvalResult:
    r = EvalResult("check_email_headers", corpus_size=len(CLEAN_HEADERS) + len(SPOOFED_HEADERS))
    for h in CLEAN_HEADERS:
        v = await _verdict("check_email_headers", raw_headers=h)
        if v == "HEADERS_CLEAN": r.tn += 1
        else: r.fp += 1
    for h in SPOOFED_HEADERS:
        v = await _verdict("check_email_headers", raw_headers=h)
        if v in ("HIGH_SPOOFING_RISK", "MODERATE_RISK"): r.tp += 1
        else: r.fn += 1
    r.notes = (
        "Parses MTA pre-evaluated auth results. "
        "Known FP source: senders with SPF pass but no DKIM/DMARC score +25; "
        "a bulk-mailer X-Mailer (+10) or >8 Received hops (+15) on top of that reaches MODERATE_RISK. "
        "Tune thresholds for environments with many small suppliers lacking DMARC."
    )
    r.notes += _error_note("check_email_headers")
    return r


# ---------------------------------------------------------------------------
# Tool 4: analyze_url_reputation (live)
# ---------------------------------------------------------------------------

async def eval_analyze_url_reputation() -> EvalResult:
    r = EvalResult("analyze_url_reputation", corpus_size=0)
    known_good = ["https://github.com", "https://anthropic.com", "https://python.org"]
    known_bad  = ["fakespotter-no-resolve-12345.invalid", "this-domain-eval-fakespotter.invalid"]

    for url in known_good:
        r.corpus_size += 1
        v = await _verdict("analyze_url_reputation", url=url)
        if v == "GOOD_REPUTATION": r.tn += 1
        else: r.fp += 1

    for domain in known_bad:
        r.corpus_size += 1
        v = await _verdict("analyze_url_reputation", url=domain)
        if v in ("POOR_REPUTATION", "MODERATE_RISK"): r.tp += 1
        else: r.fn += 1

    r.notes = (
        "Live DNS+HTTP -- not a static corpus; re-run reflects current state. "
        "Known FP source: established domains missing 2+ of 3 security headers "
        "(x-frame-options, x-content-type-options, strict-transport-security) score +10; "
        "with an HTTP 4xx/5xx (+20) that is 30, still under the 35-point MODERATE_RISK threshold. "
        "A non-resolving domain scores +30 for DNS plus +10 for the failed connection "
        "(MODERATE_RISK). Before the httpx exception fix, every failed fetch made the tool "
        "return an AttributeError instead of a verdict."
    )
    r.notes += _error_note("analyze_url_reputation")
    return r


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_table(results: list[EvalResult]) -> None:
    print(f"\n{'Tool':<35} {'N':>5} {'FP%':>7} {'FN%':>7} {'Acc%':>7}")
    print("-" * 65)
    for r in results:
        if not r.measured:
            print(f"{r.tool:<35} {'-':>5} {'not measured':>23}")
            continue
        print(f"{r.tool:<35} {r.corpus_size:>5} {r.fp_rate:>6.1f}% {r.fn_rate:>6.1f}% {r.accuracy:>6.1f}%")


def write_accuracy_md(results: list[EvalResult], path: Path) -> None:
    today = datetime.date.today().isoformat()
    lines = [
        "# FakeSpotter -- Accuracy Metrics",
        "",
        f"*Generated: {today} -- [`scripts/eval_deterministic.py`](../scripts/eval_deterministic.py)*",
        "",
        "Covers the 4 deterministic tools in the **Invoice Guard** workflow.",
        "",
        "## Results",
        "",
        "| Tool | N | FP rate | FN rate | Accuracy |",
        "|------|---|---------|---------|----------|",
    ]
    for r in results:
        if not r.measured:
            lines.append(f"| `{r.tool}` | — | not measured | not measured | not measured |")
            continue
        lines.append(f"| `{r.tool}` | {r.corpus_size} | {r.fp_rate:.1f}% | {r.fn_rate:.1f}% | {r.accuracy:.1f}% |")

    lines += ["", "## Detail and methodology", ""]
    for r in results:
        lines += [
            f"### `{r.tool}`",
            "",
            (f"N={r.corpus_size} &nbsp;.&nbsp; TP={r.tp} TN={r.tn} FP={r.fp} FN={r.fn}"
             if r.measured else "**Not measured in this run.**"),
            "",
            r.notes,
            "",
        ]

    lines += [
        "## Limitations",
        "",
        "- `analyze_url_reputation` results are time-dependent (live DNS/HTTP).",
        "- `check_email_headers` parses MTA pre-evaluated results, not live DNS.",
        "- Corpus sizes are small for CI speed; production validation needs >=500 samples per class.",
        "- Research tools (media/synthetic) are not evaluated here.",
    ]
    path.parent.mkdir(exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    print(f"\nWrote {path}")


def not_measured_url_reputation() -> EvalResult:
    r = EvalResult("analyze_url_reputation", corpus_size=0, measured=False)
    r.notes = (
        "Skipped (--skip-live): this step needs direct DNS + HTTPS access to live sites, which "
        "was not available when this file was generated. No FP/FN figure is claimed. "
        "Offline, the scoring rules are covered by tests/test_invoice_guard.py "
        "(good domain -> GOOD_REPUTATION, unresolvable + unreachable -> MODERATE_RISK, "
        "TLS failure +20). Earlier versions of this file reported 0% FP/FN for this tool; "
        "those numbers did not come from the real tool, which at the time returned "
        "'[FakeSpotter Error] AttributeError' on every failed fetch."
    )
    return r


async def main() -> None:
    print("FakeSpotter -- eval_deterministic.py")
    print("=" * 65)
    results = []
    print("\n[1/4] verify_document_integrity...")
    results.append(await eval_verify_document_integrity(100))
    print("[2/4] analyze_file_metadata...")
    results.append(await eval_analyze_file_metadata())
    print("[3/4] check_email_headers...")
    results.append(await eval_check_email_headers())
    if "--skip-live" in sys.argv[1:]:
        print("[4/4] analyze_url_reputation (live)... skipped (--skip-live)")
        results.append(not_measured_url_reputation())
    else:
        print("[4/4] analyze_url_reputation (live)...")
        results.append(await eval_analyze_url_reputation())
    print_table(results)
    docs_dir = Path(__file__).parent.parent / "docs"
    write_accuracy_md(results, docs_dir / "accuracy.md")


if __name__ == "__main__":
    asyncio.run(main())
