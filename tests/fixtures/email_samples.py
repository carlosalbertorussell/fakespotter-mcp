"""
Email header samples shared by tests/test_invoice_guard.py and
scripts/eval_deterministic.py (originally defined in eval_deterministic.py).
All domains are fictitious or reserved; no real mail is reproduced.
"""

CLEAN_HEADERS = [
    "Authentication-Results: spf=pass dkim=pass dmarc=pass\nFrom: Billing <billing@supplier.com>\nReturn-Path: <billing@supplier.com>",
    "Authentication-Results: spf=pass dkim=pass dmarc=pass\nFrom: Accounts <ap@acme.com>\nReturn-Path: <ap@acme.com>\nX-Mailer: MailChimp Mailer",
    "Authentication-Results: spf=pass dkim=none dmarc=none\nFrom: AP <ap@small-co.com>\nReturn-Path: <ap@small-co.com>",
]

SPOOFED_HEADERS = [
    "Authentication-Results: spf=fail dkim=fail dmarc=fail\nFrom: Invoice <x@supplier.com>\nReturn-Path: <b@phisher.tk>",
    "Authentication-Results: spf=fail dkim=pass dmarc=fail\nFrom: Billing <b@mybank.com>\nReturn-Path: <b@mybank.com>\nReply-To: <c@attacker.xyz>",
    "Authentication-Results: spf=softfail dkim=none dmarc=fail\nFrom: CFO <cfo@bigcorp.com>\nReturn-Path: <noreply@suspicious.net>",
    "Authentication-Results: spf=permerror dkim=fail dmarc=fail\nFrom: Support <s@paypal.com>\nReturn-Path: <x@paypa1.xyz>\nReply-To: <c@evil.ru>",
]
