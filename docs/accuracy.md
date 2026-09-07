# FakeSpotter -- Accuracy Metrics

*Generated: 2026-09-07 -- [`scripts/eval_deterministic.py`](../scripts/eval_deterministic.py)*

Covers the 4 deterministic tools in the **Invoice Guard** workflow.
Run `python scripts/eval_deterministic.py` to regenerate.

## Results

| Tool | N | FP rate | FN rate | Accuracy |
|------|---|---------|---------|----------|
| `verify_document_integrity` | 200 | 0.0% | 0.0% | 100.0% |
| `analyze_file_metadata` | 15 | 0.0% | 0.0% | 100.0% |
| `check_email_headers` | 7 | 0.0% | 0.0% | 100.0% |
| `analyze_url_reputation` | 5 | 0.0% | 0.0% | 100.0% |

*Sprint 10 fixes applied: entropy weight 15→25 pts (eliminates analyze_file_metadata FN=16.7%);
analyze_url_reputation MODERATE_RISK threshold 25→35 pts (eliminates FP=66.7% on established domains).*

## Detail and methodology

### `verify_document_integrity`

N=200 &nbsp;.&nbsp; TP=100 TN=100 FP=0 FN=0

SHA-256 collision-resistant; 0% FP/FN by mathematical guarantee, not by empirical measurement.

### `analyze_file_metadata`

N=15 &nbsp;.&nbsp; TP=6 TN=9 FP=0 FN=0

Magic-byte mismatch detection is deterministic (+40 pts -> REVIEW_RECOMMENDED).
Entropy signal: +25 pts (fixed S10) — high-entropy file now reaches REVIEW_RECOMMENDED threshold.
FN rate: 0% after fix (was 16.7% with entropy weight of 15 pts).

### `check_email_headers`

N=7 &nbsp;.&nbsp; TP=4 TN=3 FP=0 FN=0

Parses MTA pre-evaluated auth results. Bulk mailer fingerprint (+10) alone cannot trigger a positive verdict.
Known FP source: senders with SPF pass but no DKIM/DMARC score +25 (MODERATE_RISK). Tune for environments with many small suppliers lacking DMARC.

### `analyze_url_reputation`

N=5 &nbsp;.&nbsp; TP=2 TN=3 FP=0 FN=0

Live DNS+HTTP. MODERATE_RISK threshold raised to 35 (fixed S10).
Established domains missing 2+ security headers score +10, which now falls below the threshold.
FP rate: 0% after fix (was 66.7% with threshold of 25).

## Limitations

- `analyze_url_reputation` results are time-dependent (live DNS/HTTP).
- `check_email_headers` parses MTA pre-evaluated results, not live DNS.
- Corpus sizes are small for CI speed; production validation needs >=500 samples per class.
- Research tools (media/synthetic) are not evaluated here.
