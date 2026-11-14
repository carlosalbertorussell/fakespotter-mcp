# FakeSpotter -- Accuracy Metrics

*Generated: 2026-11-14 -- [`scripts/eval_deterministic.py`](../scripts/eval_deterministic.py)*

Covers the 4 deterministic tools in the **Invoice Guard** workflow.
Generated with `python scripts/eval_deterministic.py --skip-live` (offline tools only).

## Results

| Tool | N | FP rate | FN rate | Accuracy |
|------|---|---------|---------|----------|
| `verify_document_integrity` | 200 | 0.0% | 0.0% | 100.0% |
| `analyze_file_metadata` | 15 | 0.0% | 0.0% | 100.0% |
| `check_email_headers` | 7 | 0.0% | 0.0% | 100.0% |
| `analyze_url_reputation` | — | not measured | not measured | not measured |

## Detail and methodology

### `verify_document_integrity`

N=200 &nbsp;.&nbsp; TP=100 TN=100 FP=0 FN=0

SHA-256 collision-resistant; 0% FP/FN by mathematical guarantee, not by empirical measurement. Verdicts produced by the real tool.

### `analyze_file_metadata`

N=15 &nbsp;.&nbsp; TP=6 TN=9 FP=0 FN=0

Magic-byte mismatch detection is deterministic (+40 pts -> REVIEW_RECOMMENDED). Entropy signal: +25 pts (fixed in S10) — high-entropy file now reaches REVIEW_RECOMMENDED threshold. FN rate: 0% after fix (was 16.7%).

### `check_email_headers`

N=7 &nbsp;.&nbsp; TP=4 TN=3 FP=0 FN=0

Parses MTA pre-evaluated auth results. Known FP source: senders with SPF pass but no DKIM/DMARC score +25; a bulk-mailer X-Mailer (+10) or >8 Received hops (+15) on top of that reaches MODERATE_RISK. Tune thresholds for environments with many small suppliers lacking DMARC.

### `analyze_url_reputation`

**Not measured in this run.**

Skipped (--skip-live): this step needs direct DNS + HTTPS access to live sites, which was not available when this file was generated. No FP/FN figure is claimed. Offline, the scoring rules are covered by tests/test_invoice_guard.py (good domain -> GOOD_REPUTATION, unresolvable + unreachable -> MODERATE_RISK, TLS failure +20). Earlier versions of this file reported 0% FP/FN for this tool; those numbers did not come from the real tool, which at the time returned '[FakeSpotter Error] AttributeError' on every failed fetch.

*Hand-added note (2026-11-14):* the earlier 0% figures came from a
re-implementation of the scoring inside the eval script, not from the tool.
A live run of the real tool was attempted when this file was regenerated,
from a sandbox whose only egress is an HTTPS proxy. It gave TP=0 TN=3 FP=0
FN=2, but those numbers describe the proxy: both `.invalid` domains came back
as a proxy `502 Bad Gateway` (httpx `ProxyError`, which the tool flags but does
not score) instead of a connection failure, and `github.com` answered with
the proxy's HTTP 400. Re-run `python scripts/eval_deterministic.py` from a
host with direct Internet access to measure this tool.

## Limitations

- `analyze_url_reputation` results are time-dependent (live DNS/HTTP).
- `check_email_headers` parses MTA pre-evaluated results, not live DNS.
- Corpus sizes are small for CI speed; production validation needs >=500 samples per class.
- Research tools (media/synthetic) are not evaluated here.
