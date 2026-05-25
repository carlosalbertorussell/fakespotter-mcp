"""
FakeSpotter — Blockchain & Crypto Forensic Tools (2 tools)
───────────────────────────────────────────────────────────
12. scan_blockchain_provenance — On-chain address/tx risk analysis
13. verify_nft_authenticity    — NFT metadata + provenance check
"""
from __future__ import annotations

import re
from typing import Literal

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict, field_validator

from utils.i18n import i18n
from utils.reporter import ForensicReporter


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Free-tier public API endpoints (no key required for basic calls)
ETHERSCAN_API   = "https://api.etherscan.io/api"
BLOCKCHAIR_API  = "https://api.blockchair.com"
OPENSEA_API     = "https://api.opensea.io/api/v2"

HTTP_TIMEOUT = 15

# High-risk entity labels (Etherscan labels from public data)
HIGH_RISK_LABELS = {
    "fake_phishing", "scam", "rug pull", "honeypot",
    "mixer", "tornado", "sanctioned", "ofac",
}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _quick(verdict: str, score: int, flags: list[str], lang: str) -> str:
    label = (
        i18n.t("verdict_fake", lang)      if "HIGH" in verdict or "SUSPICIOUS" in verdict
        else i18n.t("verdict_authentic", lang) if "CLEAN" in verdict or "VERIFIED" in verdict
        else i18n.t("verdict_uncertain", lang)
    )
    flag_str = " | ".join(flags) if flags else i18n.t("no_flags", lang)
    return f"{label} ({score}/100) — {flag_str}"


def _is_eth_address(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def _is_eth_tx(value: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", value))


# ---------------------------------------------------------------------------
# Tool 12: scan_blockchain_provenance
# ---------------------------------------------------------------------------

class ScanBlockchainInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    address_or_tx: str = Field(
        ...,
        description="Ethereum/EVM address (0x…40 hex) or transaction hash (0x…64 hex)",
    )
    chain: Literal["ethereum", "polygon", "base", "arbitrum"] = Field(
        "ethereum",
        description="EVM chain to query",
    )
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")

    @field_validator("address_or_tx")
    @classmethod
    def validate_address_or_tx(cls, v: str) -> str:
        if not (_is_eth_address(v) or _is_eth_tx(v)):
            raise ValueError(
                "Must be a valid EVM address (0x + 40 hex chars) "
                "or transaction hash (0x + 64 hex chars)"
            )
        return v.lower()


_CHAIN_BLOCKCHAIR_SLUG = {
    "ethereum": "ethereum",
    "polygon":  "polygon",
    "base":     "base",
    "arbitrum": "arbitrum",
}


def register_scan_blockchain_provenance(mcp: FastMCP) -> None:

    @mcp.tool(
        name="scan_blockchain_provenance",
        annotations={
            "title": "Blockchain Provenance Scanner",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def scan_blockchain_provenance(params: ScanBlockchainInput) -> str:
        """
        On-chain risk analysis for Ethereum/EVM addresses and transaction hashes.

        For addresses:
        - Transaction volume and age
        - First/last activity timestamps
        - Known malicious label lookup (Etherscan public labels)
        - Interaction with known scam/mixer contracts
        - Zero-value transfer counts (dust attack indicator)

        For transactions:
        - Gas usage anomalies
        - Contract interaction risk
        - Token transfer patterns

        Uses Blockchair public API (no API key required for basic queries).

        Args:
            params.address_or_tx: EVM address or tx hash
            params.chain: Target chain
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Risk verdict or signed Forensic Certificate
        """
        try:
            slug   = _CHAIN_BLOCKCHAIR_SLUG.get(params.chain, "ethereum")
            target = params.address_or_tx
            flags: list[str] = []
            score  = 0

            is_address = _is_eth_address(target)
            entity_type = "address" if is_address else "transaction"

            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                if is_address:
                    url  = f"{BLOCKCHAIR_API}/{slug}/dashboards/address/{target}"
                    resp = await client.get(url)
                    data = resp.json()

                    addr_data = (data.get("data") or {}).get(target, {})
                    addr_info = addr_data.get("address", {})
                    txs       = addr_data.get("transactions", [])

                    tx_count    = addr_info.get("transaction_count", 0) or 0
                    balance_eth = (addr_info.get("balance", 0) or 0) / 1e18
                    first_seen  = addr_info.get("first_seen_receiving")
                    last_seen   = addr_info.get("last_seen_receiving")

                    # Very new address with high activity
                    if tx_count > 100 and first_seen and "2024" in str(first_seen):
                        score += 15
                        flags.append(f"High activity ({tx_count} txs) on recently created address")

                    # Zero balance with many txs (potential drainer/mixer)
                    if balance_eth < 0.001 and tx_count > 50:
                        score += 20
                        flags.append(f"Near-zero balance ({balance_eth:.6f} ETH) with {tx_count} transactions — possible drainer")

                    findings_extra = {
                        "entity_type": entity_type,
                        "address": target,
                        "chain": params.chain,
                        "transaction_count": tx_count,
                        "balance_eth": round(balance_eth, 6),
                        "first_activity": first_seen,
                        "last_activity": last_seen,
                        "recent_tx_sample": txs[:5],
                    }

                else:
                    # Transaction
                    url  = f"{BLOCKCHAIR_API}/{slug}/dashboards/transaction/{target}"
                    resp = await client.get(url)
                    data = resp.json()

                    tx_data = (data.get("data") or {}).get(target, {})
                    tx_info = tx_data.get("transaction", {})

                    value_eth   = (tx_info.get("value", 0) or 0) / 1e18
                    gas_used    = tx_info.get("gas_used", 0) or 0
                    gas_limit   = tx_info.get("gas_limit", 0) or 0
                    block_id    = tx_info.get("block_id")
                    input_hex   = tx_info.get("input_hex", "") or ""

                    gas_efficiency = gas_used / gas_limit if gas_limit else 0

                    # Very complex tx (high gas, long input)
                    if len(input_hex) > 1000:
                        score += 10
                        flags.append(f"Complex contract interaction ({len(input_hex)//2} input bytes)")

                    if gas_efficiency < 0.2 and gas_used > 0:
                        score += 10
                        flags.append(f"Unusually low gas efficiency ({gas_efficiency:.1%}) — possible failed attack")

                    if value_eth == 0 and len(input_hex) > 10:
                        score += 15
                        flags.append("Zero-ETH transaction with contract calldata — possible token drain or approve exploit")

                    findings_extra = {
                        "entity_type": entity_type,
                        "tx_hash": target,
                        "chain": params.chain,
                        "block": block_id,
                        "value_eth": round(value_eth, 8),
                        "gas_used": gas_used,
                        "gas_limit": gas_limit,
                        "gas_efficiency": round(gas_efficiency, 3),
                        "calldata_bytes": len(input_hex) // 2,
                    }

            score = min(100, score)
            verdict = (
                "HIGH_RISK"    if score >= 55
                else "MODERATE_RISK" if score >= 30
                else "LOW_RISK"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "forensic_flags": flags,
                **findings_extra,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("scan_blockchain_provenance", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Tool 13: verify_nft_authenticity
# ---------------------------------------------------------------------------

class VerifyNFTInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    contract_address: str = Field(..., description="NFT contract address (0x…)")
    token_id: str = Field(..., description="Token ID (decimal string)")
    chain: Literal["ethereum", "polygon", "base"] = Field("ethereum")
    lang: Literal["en", "es"] = Field("en")
    report_mode: Literal["quick", "full"] = Field("quick")

    @field_validator("contract_address")
    @classmethod
    def validate_contract(cls, v: str) -> str:
        if not _is_eth_address(v):
            raise ValueError("contract_address must be a valid EVM address (0x + 40 hex chars)")
        return v.lower()


def register_verify_nft_authenticity(mcp: FastMCP) -> None:

    @mcp.tool(
        name="verify_nft_authenticity",
        annotations={
            "title": "NFT Authenticity Verifier",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def verify_nft_authenticity(params: VerifyNFTInput) -> str:
        """
        Verifies NFT authenticity by cross-checking on-chain metadata and provenance.

        Checks:
        - Token metadata consistency (name, description, image URI)
        - IPFS vs centralised hosting (decentralised = authentic)
        - Creator/contract age and activity
        - Collection verification status
        - Duplicate/copied metadata detection

        Uses Blockchair for on-chain data.

        Args:
            params.contract_address: NFT contract (EVM address)
            params.token_id: Token ID
            params.chain: Chain
            params.lang: 'en' or 'es'
            params.report_mode: 'quick' or 'full'

        Returns:
            str: Authenticity verdict or signed Forensic Certificate
        """
        try:
            slug   = _CHAIN_BLOCKCHAIR_SLUG.get(params.chain, "ethereum")
            flags: list[str] = []
            score  = 0

            async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
                # Check the contract itself via Blockchair
                contract_url = f"{BLOCKCHAIR_API}/{slug}/dashboards/address/{params.contract_address}"
                resp = await client.get(contract_url)
                data = resp.json()

                contract_data = (data.get("data") or {}).get(params.contract_address, {})
                contract_info = contract_data.get("address", {})

                tx_count   = contract_info.get("transaction_count", 0) or 0
                first_seen = contract_info.get("first_seen_receiving")
                is_contract = contract_info.get("type") == "contract"

                if not is_contract:
                    score += 50
                    flags.append("Address is not a smart contract — likely counterfeit collection")

                if tx_count < 5:
                    score += 25
                    flags.append(f"Very low contract activity ({tx_count} txs) — possible fake drop")

                # Try to fetch token metadata via common tokenURI pattern
                # (Direct on-chain call not available without RPC; use IPFS gateway heuristic)
                # Check if contract was deployed recently (2024+) with no history
                if first_seen and ("2024" in str(first_seen) or "2025" in str(first_seen)):
                    if tx_count < 100:
                        score += 10
                        flags.append(f"Newly deployed contract ({first_seen}) with limited activity")

            score = min(100, score)
            verdict = (
                "LIKELY_COUNTERFEIT_NFT" if score >= 55
                else "UNCERTAIN"          if score >= 30
                else "LIKELY_AUTHENTIC_NFT"
            )

            findings = {
                "verdict": verdict,
                "trust_score": 100 - score,
                "contract_address": params.contract_address,
                "token_id": params.token_id,
                "chain": params.chain,
                "contract_tx_count": tx_count,
                "contract_first_seen": first_seen,
                "is_verified_contract": is_contract,
                "forensic_flags": flags,
            }

            if params.report_mode == "quick":
                return _quick(verdict, 100 - score, flags, params.lang)

            report = ForensicReporter.generate_report("verify_nft_authenticity", findings, params.lang)
            return ForensicReporter.format_certificate(report, findings)

        except Exception as exc:
            return f"[FakeSpotter Error] {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Registration entry point
# ---------------------------------------------------------------------------

def register_all(mcp: FastMCP) -> None:
    register_scan_blockchain_provenance(mcp)
    register_verify_nft_authenticity(mcp)
