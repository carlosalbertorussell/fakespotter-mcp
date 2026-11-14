"""
Gap 5a — analyze_email_thread through the MCP client API.
All addresses use fictitious example domains.
"""
from __future__ import annotations

from tests.mcp_client import call_tool


def _email(mid, date, sender, subject, refs=(), reply_to=None, received=None):
    lines = [
        f"Received: from mx.example.net by mx.buyer.example; {received or date}",
        f"Message-ID: <{mid}>",
        f"Date: {date}",
        f"From: {sender}",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if refs:
        lines.append("References: " + " ".join(f"<{r}>" for r in refs))
        lines.append(f"In-Reply-To: <{refs[-1]}>")
    lines.append(f"Subject: {subject}")
    return "\n".join(lines)


SUPPLIER = "Ana Billing <ana@supplier.example>"
BUYER = "Luis AP <luis@buyer.example>"
M1, M2, M3 = "inv-0001@supplier.example", "re-0001@buyer.example", "re2-0001@supplier.example"

MSG1 = _email(M1, "Mon, 03 Mar 2025 10:00:00 +0000", SUPPLIER, "Invoice 0001")
MSG2 = _email(M2, "Mon, 03 Mar 2025 14:30:00 +0000", BUYER, "Re: Invoice 0001", refs=[M1])
MSG3 = _email(M3, "Tue, 04 Mar 2025 09:15:00 +0000", SUPPLIER, "Re: Invoice 0001", refs=[M1, M2])


def _thread(*emails):
    return call_tool("analyze_email_thread", emails=list(emails), report_mode="full")


def test_intact_thread():
    res = _thread(MSG1, MSG2, MSG3)
    assert res.verdict == "THREAD_INTACT", res.text
    assert "Thread integrity checks passed — no manipulation signals detected" in res.text
    quick = call_tool("analyze_email_thread", emails=[MSG1, MSG2, MSG3])
    assert "THREAD_INTACT (3 messages)" in quick.text and "AUTHENTIC" in quick.text


def test_reply_to_hijack_mid_thread():
    hijacked = _email(M3, "Tue, 04 Mar 2025 09:15:00 +0000", SUPPLIER, "Re: Invoice 0001",
                      refs=[M1, M2], reply_to="Ana Billing <ana@supp1ier-payments.example>")
    res = _thread(MSG1, MSG2, hijacked)
    assert res.verdict == "THREAD_SUSPICIOUS", res.text
    assert ("Message 3: Reply-To domain (supp1ier-payments.example) differs from "
            "From domain (supplier.example) — reply hijacking") in res.text


def test_thread_insertion_impossible_back_reference():
    # A fabricated message, dated BEFORE message 3, already references message 3's ID.
    inserted = _email("fake-0001@supplier.example", "Mon, 03 Mar 2025 16:00:00 +0000", SUPPLIER,
                      "Re: Invoice 0001 - new bank details", refs=[M1, M2, M3])
    res = _thread(MSG1, MSG2, inserted, MSG3)
    assert res.verdict == "THREAD_SUSPICIOUS", res.text
    assert "THREAD INSERTION: message 3 (Date: 2025-03-03) references a message dated 17h LATER" in res.text


def test_insertion_plus_hijack_is_manipulated():
    inserted = _email("fake-0001@supplier.example", "Mon, 03 Mar 2025 16:00:00 +0000", SUPPLIER,
                      "Re: Invoice 0001", refs=[M1, M2, M3], reply_to="ana@attacker.example")
    res = _thread(MSG1, MSG2, inserted, MSG3)
    assert res.verdict == "THREAD_MANIPULATED", res.text
    assert "THREAD INSERTION" in res.text and "reply hijacking" in res.text
    quick = call_tool("analyze_email_thread", emails=[MSG1, MSG2, inserted, MSG3])
    assert "FAKE" in quick.text


def test_duplicate_message_id_and_unknown_reference():
    dup = _email(M2, "Tue, 04 Mar 2025 09:15:00 +0000", SUPPLIER, "Re: Invoice 0001",
                 refs=["never-sent@supplier.example"])
    res = _thread(MSG1, MSG2, dup)
    assert res.verdict == "THREAD_MANIPULATED", res.text  # 40 + 15
    assert f"Duplicate Message-ID(s): {M2}" in res.text
    assert "Message 3 references unknown Message-ID <never-sent@supplier.example>" in res.text


def test_backdated_date_vs_received():
    backdated = _email(M3, "Sat, 01 Feb 2025 09:15:00 +0000", SUPPLIER, "Re: Invoice 0001",
                       refs=[M1, M2], received="Tue, 04 Mar 2025 09:15:00 +0000")
    res = _thread(MSG1, MSG2, backdated)
    assert "Message 3: Date header (2025-02-01)" in res.text and "possible backdating" in res.text


def test_new_sender_domain_mid_thread():
    outsider = _email(M3, "Tue, 04 Mar 2025 09:15:00 +0000", "Ana <ana@supplier-mail.example>",
                      "Re: Invoice 0001", refs=[M1, M2])
    res = _thread(MSG1, MSG2, outsider)
    assert res.verdict == "THREAD_INTACT", res.text  # +10 only
    assert "New sender domain in message 3: supplier-mail.example" in res.text


def test_thread_needs_two_emails():
    res = call_tool("analyze_email_thread", emails=[MSG1])
    assert res.is_error
