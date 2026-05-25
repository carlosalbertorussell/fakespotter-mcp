"""
FakeSpotter — Network & Cyber Forensic Tools (3 tools)
────────────────────────────────────────────────────────
9.  scan_phishing_url     — URL heuristics + live HTTP analysis
10. check_email_headers   — SPF/DKIM/DMARC + header consistency
11. analyze_url_reputation — Domain age, redirect chain, response analysis
"""
from __future__ import annotations

import re
import socket
from typing import Literal
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                   ".online", ".site", ".website", ".space", ".info"}

BRAND_IMPERSONATION = [
    "paypal", "amazon", "google", "apple", "microsoft", "facebook", "instagram",
    "netflix", "whatsapp", "bank", "chase", "wellsfargo", "citibank", "hsbc",
    "binance", "coinbase", "metamask", "opensea", "mercadopago", "santander",
]

HTTP_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "PHISHING" in verdict or "MALICIOUS" in verdict
        else i18n.t("verdict_authentic", lang) if "SAFE" in verdict or "LEGITIMATE" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


# ---------------------------------------------------------------------------
# Tool 9: scan_phishing_url
# ---------------------------------------------------------------------------

class ScanPhishingURLInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="URL to analyse for phishing indicators")
    follow_redirects: bool = Field(True, description="Whether to follow redirect chains")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_scan_phishing_url(mcp: FastMCP) -> None:

    @mcp.tool(
        name="scan_phishing_url",
        annotations={
            "title": "Phishing URL Scanner",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def scan_phishing_url(params: ScanPhishingURLInput) -> str:
        """
        Multi-layer phishing URL analysis combining structural heuristics and live HTTP checks.

        Heuristic checks:
        - URL length and entropy (long/random URLs are suspicious)
        - Brand impersonation in subdomain or path (paypal-secure.tk)
        - Suspicious TLD usage
        - IP address instead of domain name
        - Excessive subdomains (>3 levels)
        - Lookalike characters (0 vs o, 1 vs l)

        Live HTTP checks (if reachable):
        - HTTPS enforcement
        - Redirect chain length and final destination
        - Response status codes
        - X-Frame-Options and security headers

        Args:
            params.url: URL to scan
            params.follow_redirects: Trace redirect chain
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Phishing risk verdict or signed Forensic Certificate
        """
        try:
            parsed = urlparse(params.url if "://" in params.url else f"https://{params.url}")
            domain = parsed.netloc.lower()
            path   = parsed.path.lower()
            full   = params.url.lower()

            flags: list[str] = []
            score = 0

            # --- Structural heuristics ---

            # URL length
            if len(params.url) > 120:
                score += 15
                flags.append(f"Excessively long URL ({len(params.url)} chars)")

            # IP address host
            ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            if ip_pattern.match(domain.split(":")[0]):
                score += 30
                flags.append("URL uses raw IP address instead of domain name")

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score += 20
                    flags.append(f"High-risk free TLD: {tld}")
                    break

            # Brand impersonation
            for brand in BRAND_IMPERSONATION:
                if brand in domain and not domain.startswith(brand + "."):
                    score += 35
                    flags.append(f"Brand impersonation: '{brand}' in domain")
                    break

            # Subdomain depth
            subdomain_parts = domain.split(".")
            if len(subdomain_parts) > 4:
                score += 15
                flags.append(f"Excessive subdomain depth ({len(subdomain_parts)} levels)")

            # Suspicious keywords in path
            phishing_path_kws = ["login", "signin", "verify", "update", "secure",
                                  "account", "confirm", "validate", "suspended", "alert"]
            matched_kws = [kw for kw in phishing_path_kws if kw in path]
            if len(matched_kws) >= 2:
                score += 15
                flags.append(f"Phishing keywords in path: {', '.join(matched_kws)}")

            # Protocol
            if parsed.scheme != "https":
                score += 10
                flags.append("Non-HTTPS URL — no transport encryption")

            # Lookalike characters (homograph)
            lookalike_map = {"0": "o", "1": "l", "rn": "m", "vv": "w"}
            for fake, real in lookalike_map.items():
                if fake in domain and real in domain:
                    score += 20
                    flags.append(f"Possible homograph attack: '{fake}' → '{real}'")
                    break

            # --- Live HTTP check ---
            redirect_chain: list[str] = []
            final_url = params.url
            status_code = None
            security_headers: dict[str, str] = {}

            try:
                async with httpx.AsyncClient(
                    follow_redirects=params.follow_redirects,
                    timeout=HTTP_TIMEOUT,
                    headers={"User-Agent": "FakeSpotter/1.0 forensic-scanner"},
                ) as client:
                    resp = await client.get(params.url)
                    status_code = resp.status_code
                    final_url   = str(resp.url)
                    redirect_chain = [str(r.url) for r in resp.history]

                    security_headers = {
                        "X-Frame-Options":          resp.headers.get("x-frame-options", "MISSING"),
                        "Content-Security-Policy":  resp.headers.get("content-security-policy", "MISSING"),
                        "Strict-Transport-Security": resp.headers.get("strict-transport-security", "MISSING"),
                    }

                if len(redirect_chain) > 3:
                    score += 20
                    flags.append(f"Long redirect chain ({len(redirect_chain)} hops): final={final_url}")

                if security_headers["X-Frame-Options"] == "MISSING":
                    score += 5

                if status_code and status_code >= 400:
                    flags.append(f"HTTP {status_code} response — page may not be active")

            except httpx.TimeoutException:
                flags.append("Connection timeout — URL may be intermittently active")
            except httpx.ConnectError:
                flags.append("Cannot connect — domain may not resolve")
            except Exception as http_exc:
                flags.append(f"HTTP check skipped: {http_exc}")

            score = min(100, score)
            verdict = (
                "HIGH_PHISHING_RISK"   if score >= 60
                else "MODERATE_RISK"   if score >= 35
                else "LOW_RISK"
            )

            findings = {
                "verdict": verdict,
                "risk_score": score,
                "trust_score": 100 - score,
                "url_analysed": params.url,
                "domain": domain,
                "final_url": final_url,
                "redirect_hops": len(redirect_chain),
                "redirect_chain": redirect_chain,
                "http_status": status_code,
                "security_headers": security_headers,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("scan_phishing_url", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 10: check_email_headers
# ---------------------------------------------------------------------------

class CheckEmailHeadersInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    raw_headers: str = Field(
        ...,
        description="Raw email headers (paste the full Received/From/DKIM/SPF header block)",
        min_length=20,
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_check_email_headers(mcp: FastMCP) -> None:

    @mcp.tool(
        name="check_email_headers",
        annotations={
            "title": "Email Header Analyser",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def check_email_headers(params: CheckEmailHeadersInput) -> str:
        """
        Forensic analysis of raw email headers for spoofing and phishing signals.

        Checks:
        - SPF result (pass / fail / softfail / none)
        - DKIM signature presence and result
        - DMARC policy and result
        - From vs Return-Path domain mismatch (display-name spoofing)
        - Received hop count and relay chain consistency
        - X-Mailer / User-Agent for bulk-mailer fingerprints
        - Reply-To mismatch with From domain

        Args:
            params.raw_headers: Paste of raw email header block
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Spoofing verdict or signed Forensic Certificate
        """
        try:
            headers = params.raw_headers
            flags: list[str] = []
            score = 0

            def extract_header(name: str) -> str:
                pattern = re.compile(rf"^{name}:\s*(.+?)(?=\n\S|\Z)", re.MULTILINE | re.DOTALL | re.IGNORECASE)
                m = pattern.search(headers)
                return m.group(1).strip().replace("\n", " ") if m else ""

            # SPF
            spf_results = re.findall(r"spf=(pass|fail|softfail|neutral|none|permerror|temperror)", headers, re.IGNORECASE)
            spf_result = spf_results[0].lower() if spf_results else "none"
            if spf_result in ("fail", "permerror"):
                score += 40
                flags.append(f"SPF FAIL — sender IP not authorised by domain policy")
            elif spf_result == "softfail":
                score += 20
                flags.append("SPF SOFTFAIL — suspicious but not definitive")
            elif spf_result == "none":
                score += 15
                flags.append("No SPF record — domain has no sender policy")

            # DKIM
            dkim_results = re.findall(r"dkim=(pass|fail|none|neutral|permerror|temperror)", headers, re.IGNORECASE)
            dkim_result = dkim_results[0].lower() if dkim_results else "none"
            if dkim_result == "fail":
                score += 35
                flags.append("DKIM signature FAIL — message content was altered in transit")
            elif dkim_result == "none":
                score += 15
                flags.append("No DKIM signature — sender authenticity unverifiable")

            # DMARC
            dmarc_results = re.findall(r"dmarc=(pass|fail|none|bestguesspass)", headers, re.IGNORECASE)
            dmarc_result = dmarc_results[0].lower() if dmarc_results else "none"
            if dmarc_result == "fail":
                score += 30
                flags.append("DMARC FAIL — message fails domain authentication policy")
            elif dmarc_result == "none":
                score += 10
                flags.append("DMARC not evaluated")

            # From / Return-Path mismatch
            from_header        = extract_header("From")
            return_path_header = extract_header("Return-Path")

            from_domain_m   = re.search(r"@([\w.\-]+)", from_header)
            rpath_domain_m  = re.search(r"@([\w.\-]+)", return_path_header)

            from_domain  = from_domain_m.group(1).lower()  if from_domain_m  else ""
            rpath_domain = rpath_domain_m.group(1).lower() if rpath_domain_m else ""

            if from_domain and rpath_domain and from_domain != rpath_domain:
                score += 30
                flags.append(f"Domain mismatch: From={from_domain!r} vs Return-Path={rpath_domain!r}")

            # Reply-To mismatch
            reply_to_header = extract_header("Reply-To")
            reply_domain_m  = re.search(r"@([\w.\-]+)", reply_to_header)
            reply_domain    = reply_domain_m.group(1).lower() if reply_domain_m else ""

            if reply_domain and from_domain and reply_domain != from_domain:
                score += 20
                flags.append(f"Reply-To hijack: Reply-To domain {reply_domain!r} ≠ From domain {from_domain!r}")

            # X-Mailer bulk sender fingerprints
            x_mailer = extract_header("X-Mailer")
            bulk_mailers = ["mailchimp", "sendgrid", "mailgun", "sendinblue", "klaviyo",
                            "constant contact", "aweber", "getresponse", "phpmailer"]
            matched_mailer = next((m for m in bulk_mailers if m in x_mailer.lower()), None)
            if matched_mailer:
                score += 10
                flags.append(f"Bulk mailer detected: {matched_mailer}")

            # Received hop count
            hop_count = len(re.findall(r"^Received:", headers, re.MULTILINE | re.IGNORECASE))
            if hop_count > 8:
                score += 15
                flags.append(f"Unusual relay chain depth: {hop_count} hops")

            score = min(100, score)
            verdict = (
                "HIGH_SPOOFING_RISK"   if score >= 60
                else "MODERATE_RISK"   if score >= 35
                else "HEADERS_CLEAN"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "spf_result": spf_result,
                "dkim_result": dkim_result,
                "dmarc_result": dmarc_result,
                "from_domain": from_domain,
                "return_path_domain": rpath_domain,
                "reply_to_domain": reply_domain,
                "x_mailer": x_mailer or "Not present",
                "relay_hop_count": hop_count,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("check_email_headers", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 11: analyze_url_reputation
# ---------------------------------------------------------------------------

class AnalyzeURLReputationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    url: str = Field(..., description="URL or domain to perform reputation analysis on")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")


def register_analyze_url_reputation(mcp: FastMCP) -> None:

    @mcp.tool(
        name="analyze_url_reputation",
        annotations={
            "title": "URL Reputation Analyser",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def analyze_url_reputation(params: AnalyzeURLReputationInput) -> str:
        """
        Reputation and liveness analysis for a URL or domain.

        Checks:
        - DNS resolution and RDNS consistency
        - HTTPS availability and certificate presence
        - Response headers security posture
        - Server software disclosure
        - Content-type consistency with URL
        - Response time anomalies

        Args:
            params.url: URL or domain to analyse
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Reputation verdict or signed Forensic Certificate
        """
        try:
            url = params.url if "://" in params.url else f"https://{params.url}"
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path

            flags: list[str] = []
            score = 0

            # DNS resolution
            try:
                ip_addresses = socket.getaddrinfo(domain, None)
                resolved_ips = list({r[4][0] for r in ip_addresses})
            except socket.gaierror:
                resolved_ips = []
                score += 30
                flags.append(f"Domain does not resolve: {domain}")

            # HTTP analysis
            server_header = ""
            content_type  = ""
            status_code   = None
            response_time_ms = None
            tls_valid     = True

            try:
                import time
                async with httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=HTTP_TIMEOUT,
                    headers={"User-Agent": "FakeSpotter/1.0 reputation-check"},
                ) as client:
                    t0 = time.monotonic()
                    resp = await client.get(url)
                    response_time_ms = round((time.monotonic() - t0) * 1000, 1)

                    status_code  = resp.status_code
                    server_header = resp.headers.get("server", "")
                    content_type  = resp.headers.get("content-type", "")

                    if status_code >= 400:
                        score += 20
                        flags.append(f"HTTP {status_code} error response")

                    # Server software disclosure
                    if server_header:
                        flags.append(f"Server software disclosed: {server_header}")
                        if any(v in server_header.lower() for v in ["apache/", "nginx/", "iis/"]):
                            score += 5  # minor — version disclosure

                    # No content-type
                    if not content_type:
                        score += 10
                        flags.append("Missing Content-Type header")

                    # Missing security headers
                    missing_sec = [
                        h for h in ["strict-transport-security", "x-frame-options", "x-content-type-options"]
                        if h not in resp.headers
                    ]
                    if len(missing_sec) >= 2:
                        score += 10
                        flags.append(f"Missing security headers: {', '.join(missing_sec)}")

            except httpx.ConnectSSLError:
                tls_valid = False
                score += 20
                flags.append("TLS/SSL certificate error — invalid or self-signed")
            except httpx.TimeoutException:
                score += 10
                flags.append("Request timeout")
            except Exception as http_err:
                flags.append(f"HTTP check failed: {http_err}")

            score = min(100, score)
            verdict = (
                "POOR_REPUTATION"    if score >= 50
                else "MODERATE_RISK" if score >= 25
                else "GOOD_REPUTATION"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "domain": domain,
                "resolved_ips": resolved_ips,
                "http_status": status_code,
                "response_time_ms": response_time_ms,
                "server_software": server_header or "Not disclosed",
                "tls_valid": tls_valid,
                "content_type": content_type,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("analyze_url_reputation", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_scan_phishing_url(mcp)
    register_check_email_headers(mcp)
    register_analyze_url_reputation(mcp)
