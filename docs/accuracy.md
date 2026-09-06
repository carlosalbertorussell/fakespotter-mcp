# FakeSpotter -- Accuracy Metrics

*Generated: 2026-09-06 -- [`scripts/eval_deterministic.py`](../scripts/eval_deterministic.py)*

Covers the 4 deterministic tools in the **Invoice Guard** workflow.

## Results

| Tool | N | FP rate | FN rate | Accuracy |
|------|---|---------|---------|----------|
| `verify_document_integrity` | 200 | 0.0% | 0.0% | 100.0% |
| `analyze_file_metadata` | 15 | 0.0% | 16.7% | 93.3% |
| `check_email_headers` | 7 | 0.0% | 0.0% | 100.0% |
| `analyze_url_reputation` | 5 | 66.7% | 0.0% | 60.0% |

## Detail and methodology

### `verify_document_integrity`

N=200 &nbsp;.&nbsp; TP=100 TN=100 FP=0 FN=0

SHA-256 collision-resistant; 0% FP/FN by mathematical guarantee, not by empirical measurement.

### `analyze_file_metadata`

N=15 &nbsp;.&nbsp; TP=5 TN=9 FP=0 FN=1

Magic-byte mismatch detection is deterministic (+40 pts -> REVIEW_RECOMMENDED). Known FN source: entropy-only signal (+15 pts) falls below REVIEW_RECOMMENDED threshold (25 pts) when no extension mismatch is present. Fix: raise entropy weight to 25 pts or lower threshold.

### `check_email_headers`

N=7 &nbsp;.&nbsp; TP=4 TN=3 FP=0 FN=0

Parses MTA pre-evaluated auth results. Known FP source: senders with SPF pass but no DKIM/DMARC score +25 (MODERATE_RISK). Tune thresholds for environments with many small suppliers lacking DMARC.

### `analyze_url_reputation`

N=5 &nbsp;.&nbsp; TP=2 TN=1 FP=2 FN=0

Live DNS+HTTP -- not a static corpus; re-run reflects current state. Known FP source: established domains missing 2+ of 3 security headers (x-frame-options, x-content-type-options, strict-transport-security) score MODERATE_RISK (+10). Recommendation: raise MODERATE_RISK threshold from 25 to 35 for the reputation check.

## Limitations

- `analyze_url_reputation` results are time-dependent (live DNS/HTTP).
- `check_email_headers` parses MTA pre-evaluated results, not live DNS.
- Corpus sizes are small for CI speed; production validation needs >=500 samples per class.
- Research tools (media/synthetic) are not evaluated here.
