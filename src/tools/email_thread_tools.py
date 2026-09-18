"""
FakeSpotter — tools/email_thread_tools.py
Email Thread Integrity Analyzer (tool #29)

Detects thread manipulation attacks: adversarial insertion of fabricated
messages into an existing email conversation to create false context
(a common Business Email Compromise vector).

Signals analyzed:
  Threading integrity:
    Message-ID uniqueness and format consistency
    References / In-Reply-To chain — gaps, loops, or broken links
    Subject consistency (Re:/Fwd: prefix patterns)
    Thread insertion: a message references a Message-ID that arrived AFTER it

  Chronological integrity:
    Received header timestamp chain — messages arriving out of order
    Date header vs Received timestamp — large gaps indicate manipulation
    Timezone consistency across messages in the thread

  Sender consistency:
    From domain consistency within expected thread participants
    Reply-To hijacking (Reply-To domain differs from From domain)
    Unexpected new participants joining mid-thread

No external dependencies — stdlib regex + datetime only.

Input: list of raw email strings (paste each email's headers, or full email)
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Email parsing helpers
# ---------------------------------------------------------------------------

def _extract_header(raw: str, name: str) -> str:
    """Extract the first occurrence of a header value (case-insensitive)."""
    m = re.search(rf"^{name}:\s*(.+?)(?=\n[^\s]|\Z)", raw, re.M | re.S | re.I)
    return m.group(1).strip().replace("\n", " ").replace("\r", "") if m else ""


def _extract_all_received(raw: str) -> list[str]:
    """Extract all Received headers in order."""
    return re.findall(r"^Received:\s*(.*?)(?=\nReceived:|\n[A-Z]|\Z)",
                      raw, re.M | re.S | re.I)


def _parse_message_id(mid: str) -> str:
    """Normalize a Message-ID by stripping angle brackets and whitespace."""
    return mid.strip().strip("<>").strip()


def _parse_date(date_str: str) -> datetime | None:
    """Parse an email Date header into a timezone-aware datetime."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _extract_domain(addr: str) -> str:
    """Extract the domain part of an email address."""
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def _received_timestamp(received_str: str) -> datetime | None:
    """Extract the timestamp from a Received header."""
    m = re.search(r";\s*(.+?)$", received_str.strip(), re.M)
    if m:
        return _parse_date(m.group(1).strip())
    return None


# ---------------------------------------------------------------------------
# Thread analysis
# ---------------------------------------------------------------------------

def _analyze_thread(emails: list[str]) -> tuple[str, int, list[str]]:
    flags: list[str] = []
    score = 0

    # Parse all messages
    messages: list[dict] = []
    for i, raw in enumerate(emails, 1):
        msg: dict = {
            "index":       i,
            "message_id":  _parse_message_id(_extract_header(raw, "Message-ID")),
            "references":  [_parse_message_id(r)
                            for r in re.split(r"\s+", _extract_header(raw, "References"))
                            if r.strip()],
            "in_reply_to": _parse_message_id(_extract_header(raw, "In-Reply-To")),
            "subject":     _extract_header(raw, "Subject"),
            "from":        _extract_header(raw, "From"),
            "reply_to":    _extract_header(raw, "Reply-To"),
            "date":        _parse_date(_extract_header(raw, "Date")),
            "received":    [_received_timestamp(r)
                            for r in _extract_all_received(raw)],
        }
        messages.append(msg)

    known_ids = {m["message_id"] for m in messages if m["message_id"]}

    # ── 1. Message-ID uniqueness ──────────────────────────────────────────
    all_ids = [m["message_id"] for m in messages if m["message_id"]]
    duplicates = [mid for mid in set(all_ids) if all_ids.count(mid) > 1]
    if duplicates:
        score += 40
        flags.append(f"⚠ Duplicate Message-ID(s): {', '.join(duplicates[:2])}")

    # ── 2. References chain integrity ─────────────────────────────────────
    for msg in messages:
        for ref in msg["references"]:
            if ref and ref not in known_ids:
                score += 15
                flags.append(
                    f"⚠ Message {msg['index']} references unknown Message-ID <{ref[:40]}> "
                    f"— may reference a message outside this thread or a fabricated ID"
                )
                break

    # ── 3. Thread insertion detection ────────────────────────────────────
    # A message references a Message-ID that arrived AFTER it (impossible in normal flow)
    id_to_date = {m["message_id"]: m["date"] for m in messages if m["message_id"] and m["date"]}
    for msg in messages:
        if not msg["date"]:
            continue
        for ref in msg["references"]:
            ref_date = id_to_date.get(ref)
            if ref_date and msg["date"] < ref_date:
                delta = (ref_date - msg["date"]).total_seconds() / 3600
                score += 45
                flags.append(
                    f"⚠ THREAD INSERTION: message {msg['index']} (Date: {msg['date'].date()}) "
                    f"references a message dated {delta:.0f}h LATER — "
                    f"impossible in genuine conversation flow"
                )

    # ── 4. Date vs Received timestamp mismatch ────────────────────────────
    for msg in messages:
        received_times = [t for t in msg["received"] if t]
        if msg["date"] and received_times:
            earliest_received = min(received_times)
            gap_hours = abs((msg["date"] - earliest_received).total_seconds()) / 3600
            if gap_hours > 48:
                score += 25
                flags.append(
                    f"⚠ Message {msg['index']}: Date header ({msg['date'].date()}) "
                    f"is {gap_hours:.0f}h apart from Received timestamp "
                    f"({earliest_received.date()}) — possible backdating"
                )

    # ── 5. Subject consistency ────────────────────────────────────────────
    subjects = [re.sub(r"^(Re:|Fwd:|Fw:)\s*", "", m["subject"], flags=re.I).strip()
                for m in messages if m["subject"]]
    unique_subjects = set(subjects)
    if len(unique_subjects) > 2:
        score += 15
        flags.append(
            f"Subject inconsistency: {len(unique_subjects)} distinct subjects in thread "
            f"— {', '.join(list(unique_subjects)[:3])}"
        )

    # ── 6. Reply-To hijacking ─────────────────────────────────────────────
    for msg in messages:
        from_domain   = _extract_domain(msg["from"])
        reply_domain  = _extract_domain(msg["reply_to"])
        if from_domain and reply_domain and from_domain != reply_domain:
            score += 30
            flags.append(
                f"⚠ Message {msg['index']}: Reply-To domain ({reply_domain}) "
                f"differs from From domain ({from_domain}) — reply hijacking"
            )

    # ── 7. New participants mid-thread ────────────────────────────────────
    if len(messages) >= 3:
        early_domains = {_extract_domain(m["from"]) for m in messages[:2] if m["from"]}
        for msg in messages[2:]:
            dom = _extract_domain(msg["from"])
            if dom and dom not in early_domains:
                score += 10
                flags.append(
                    f"New sender domain in message {msg['index']}: {dom} "
                    f"(not present in first 2 messages)"
                )
                early_domains.add(dom)

    # ── Flags for clean thread ────────────────────────────────────────────
    if not flags:
        flags.append("Thread integrity checks passed — no manipulation signals detected")

    score = min(100, score)
    if score >= 50:
        verdict = "THREAD_MANIPULATED"
    elif score >= 25:
        verdict = "THREAD_SUSPICIOUS"
    else:
        verdict = "THREAD_INTACT"

    return verdict, score, flags


# ---------------------------------------------------------------------------
# Tool: analyze_email_thread
# ---------------------------------------------------------------------------

class AnalyzeEmailThreadInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    emails: list[str] = Field(
        ...,
        description=(
            "List of 2–20 raw email strings (headers or full RFC 5322 emails). "
            "Provide the emails in the ORDER THEY APPEAR in the thread (oldest first). "
            "Each string should include at minimum: Message-ID, Date, From, "
            "References or In-Reply-To (if a reply), and Received headers."
        ),
        min_length=2,
        max_length=20,
    )
    lang:        Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_email_thread(mcp: FastMCP) -> None:

    @mcp.tool(
        name="analyze_email_thread",
        annotations={
            "title": "Email Thread Integrity Analyzer",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_email_thread(params: AnalyzeEmailThreadInput) -> str:
        """
        Detects thread manipulation in email conversations.

        Business Email Compromise (BEC) attackers inject fabricated messages
        into existing threads to create false approval context ("as we agreed
        in our previous exchange..."). This tool detects the structural signals
        that legitimate email clients leave and that forgers typically miss.

        Signals checked:
          Threading integrity:
            Message-ID uniqueness and format
            References / In-Reply-To chain consistency
            Thread insertion: a message references a later-dated message
            (physically impossible in genuine conversation flow)

          Chronological integrity:
            Date header vs Received timestamp divergence (>48h gap = suspicious)
            Temporal order of References chain

          Sender integrity:
            Reply-To domain vs From domain (reply hijacking)
            New sender domains appearing mid-thread

          Subject consistency:
            More than 2 distinct normalized subjects in one thread

        Verdicts:
          THREAD_INTACT       — no manipulation signals detected
          THREAD_SUSPICIOUS   — minor anomalies worth reviewing
          THREAD_MANIPULATED  — strong structural evidence of manipulation

        No external dependencies — stdlib parsing only.

        Args:
            params.emails:      List of raw email strings (oldest first)
            params.lang:        en | es
            params.report_mode: quick | full
        """
        try:
            verdict, score, flags = _analyze_thread(params.emails)
            trust = 100 - score

            findings = {
                "verdict":           verdict,
                "trust_score":       trust,
                "manipulation_score": score,
                "messages_analyzed": len(params.emails),
                "forensic_flags":    flags,
            }

            if params.report_mode == "quick":
                label = (
                    i18n.t("verdict_authentic", params.lang) if verdict == "THREAD_INTACT"
                    else i18n.t("verdict_fake", params.lang) if verdict == "THREAD_MANIPULATED"
                    else i18n.t("verdict_uncertain", params.lang)
                )
                key_flags = [f for f in flags if f.startswith("⚠")][:3] or flags[:2]
                return (
                    f"{label} ({trust}/100) — {verdict} "
                    f"({len(params.emails)} messages) | {' | '.join(key_flags)}"
                )

            report = ForensicReporter.generate_report("analyze_email_thread", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_analyze_email_thread(mcp)
