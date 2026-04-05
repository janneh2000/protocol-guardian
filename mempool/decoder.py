"""
Protocol Guardian v2 — Transaction Decoder & Threat Analyzer
=============================================================
Decodes pending transactions from the mempool and produces
structured threat intelligence for the Claude risk scorer.

Pipeline: raw tx → decode calldata → match patterns → score → report
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional

from .patterns import (
    AttackCategory,
    ExploitSignature,
    BehavioralPattern,
    BEHAVIORAL_PATTERNS,
    match_selector,
    match_all_selectors,
)

logger = logging.getLogger("guardian.decoder")


# ─────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────

@dataclass
class DecodedTransaction:
    """A pending transaction decoded from the mempool."""
    tx_hash: str
    from_address: str
    to_address: Optional[str]
    value_wei: int
    value_eth: float
    gas_price_gwei: float
    max_priority_fee_gwei: float
    gas_limit: int
    nonce: int
    calldata: str
    calldata_size: int
    input_selector: Optional[str]
    timestamp: float = field(default_factory=time.time)

    @property
    def is_contract_creation(self) -> bool:
        return self.to_address is None

    @property
    def has_calldata(self) -> bool:
        return self.calldata_size > 0


@dataclass
class ThreatIndicator:
    """A single threat signal found in a transaction."""
    source: str                 # "selector_match" | "behavioral" | "calldata_scan"
    category: AttackCategory
    risk_weight: float
    description: str
    evidence: str               # The specific data that triggered this indicator
    references: list[str] = field(default_factory=list)


@dataclass
class ThreatReport:
    """Complete threat analysis for a single pending transaction."""
    tx: DecodedTransaction
    indicators: list[ThreatIndicator]
    composite_risk_score: float     # 0.0 - 1.0
    risk_level: str                 # "low" | "medium" | "high" | "critical"
    attack_categories: list[str]
    recommended_action: str
    analysis_latency_ms: float
    claude_context: str             # Pre-formatted context string for Claude

    @property
    def is_threat(self) -> bool:
        return self.composite_risk_score >= 0.4

    @property
    def is_critical(self) -> bool:
        return self.composite_risk_score >= 0.8


# ─────────────────────────────────────────────────────────
# Decoder
# ─────────────────────────────────────────────────────────

class TransactionDecoder:
    """Decodes raw Ethereum transactions into structured data."""

    def decode(self, raw_tx: dict) -> DecodedTransaction:
        """Parse a raw pending transaction from the node."""
        calldata = raw_tx.get("input", "0x")
        value_wei = int(raw_tx.get("value", "0x0"), 16)
        gas_price = int(raw_tx.get("gasPrice", "0x0"), 16)
        max_priority = int(raw_tx.get("maxPriorityFeePerGas", "0x0"), 16)

        selector = None
        if calldata and len(calldata) >= 10:
            selector = calldata[:10].lower()

        return DecodedTransaction(
            tx_hash=raw_tx.get("hash", ""),
            from_address=raw_tx.get("from", "").lower(),
            to_address=raw_tx.get("to", "").lower() if raw_tx.get("to") else None,
            value_wei=value_wei,
            value_eth=value_wei / 1e18,
            gas_price_gwei=gas_price / 1e9,
            max_priority_fee_gwei=max_priority / 1e9,
            gas_limit=int(raw_tx.get("gas", "0x0"), 16),
            nonce=int(raw_tx.get("nonce", "0x0"), 16),
            calldata=calldata,
            calldata_size=max(0, (len(calldata) - 2) // 2),  # bytes
            input_selector=selector,
        )


# ─────────────────────────────────────────────────────────
# Threat Analyzer
# ─────────────────────────────────────────────────────────

class ThreatAnalyzer:
    """
    Multi-vector threat analysis engine.
    Combines selector matching, calldata scanning, and behavioral
    heuristics to produce a composite risk score.
    """

    def __init__(
        self,
        watched_contracts: set[str],
        base_fee_gwei: float = 30.0,
        high_value_threshold_eth: float = 100.0,
    ):
        self.watched_contracts = {addr.lower() for addr in watched_contracts}
        self.base_fee_gwei = base_fee_gwei
        self.high_value_threshold_eth = high_value_threshold_eth

        # Track recent addresses for behavioral analysis
        self._recent_senders: dict[str, list[float]] = {}
        self._recent_targets: dict[str, list[str]] = {}

    def update_base_fee(self, base_fee_gwei: float):
        """Update the current base fee for gas-based heuristics."""
        self.base_fee_gwei = base_fee_gwei

    def analyze(self, tx: DecodedTransaction) -> ThreatReport:
        """Full threat analysis pipeline for a decoded transaction."""
        start = time.monotonic()
        indicators: list[ThreatIndicator] = []

        # Skip if not targeting a watched contract
        targets_watched = (
            tx.to_address is not None
            and tx.to_address in self.watched_contracts
        )

        # Phase 1: Primary selector match
        if tx.has_calldata:
            primary = match_selector(tx.calldata)
            if primary:
                indicators.append(ThreatIndicator(
                    source="selector_match",
                    category=primary.category,
                    risk_weight=primary.risk_weight,
                    description=primary.description,
                    evidence=f"Selector {primary.selector} → {primary.signature}",
                    references=primary.references,
                ))

        # Phase 2: Deep calldata scan for embedded selectors
        if tx.has_calldata and tx.calldata_size > 36:
            embedded = match_all_selectors(tx.calldata)
            for sig in embedded:
                if not any(i.evidence.startswith(f"Selector {sig.selector}") for i in indicators):
                    indicators.append(ThreatIndicator(
                        source="calldata_scan",
                        category=sig.category,
                        risk_weight=sig.risk_weight * 0.8,  # Slightly lower confidence for embedded
                        description=f"Embedded call: {sig.description}",
                        evidence=f"Nested selector {sig.selector} → {sig.signature}",
                        references=sig.references,
                    ))

        # Phase 3: Behavioral heuristics
        indicators.extend(self._check_behavioral(tx))

        # Phase 4: Multi-vector amplification
        # If we see flash_loan + oracle_manipulation in same tx, amplify
        categories_found = {i.category for i in indicators}
        if len(categories_found) >= 2:
            combos = self._check_attack_combos(categories_found)
            indicators.extend(combos)

        # Phase 5: Watched contract targeting bonus
        if targets_watched and indicators:
            for ind in indicators:
                ind.risk_weight = min(1.0, ind.risk_weight * 1.3)

        # Compute composite score
        score = self._compute_score(indicators)
        level = self._score_to_level(score)
        action = self._recommend_action(score, categories_found, targets_watched)
        latency = (time.monotonic() - start) * 1000

        # Build Claude context
        claude_ctx = self._build_claude_context(tx, indicators, score, level)

        # Track sender for behavioral analysis
        self._track_sender(tx)

        return ThreatReport(
            tx=tx,
            indicators=indicators,
            composite_risk_score=round(score, 4),
            risk_level=level,
            attack_categories=sorted(set(i.category.value for i in indicators)),
            recommended_action=action,
            analysis_latency_ms=round(latency, 2),
            claude_context=claude_ctx,
        )

    def _check_behavioral(self, tx: DecodedTransaction) -> list[ThreatIndicator]:
        """Check transaction metadata against behavioral patterns."""
        indicators = []

        # High gas priority (front-running indicator)
        if self.base_fee_gwei > 0 and tx.gas_price_gwei > self.base_fee_gwei * 3:
            indicators.append(ThreatIndicator(
                source="behavioral",
                category=AttackCategory.FRONT_RUNNING,
                risk_weight=0.4,
                description="Gas price 3x+ above base fee — possible front-running",
                evidence=f"Gas: {tx.gas_price_gwei:.1f} gwei vs base: {self.base_fee_gwei:.1f} gwei",
            ))

        # Large value transfer
        if tx.value_eth > self.high_value_threshold_eth:
            indicators.append(ThreatIndicator(
                source="behavioral",
                category=AttackCategory.FLASH_LOAN,
                risk_weight=0.5,
                description=f"High-value transfer: {tx.value_eth:.2f} ETH",
                evidence=f"Value: {tx.value_eth:.2f} ETH (threshold: {self.high_value_threshold_eth})",
            ))

        # Contract creation
        if tx.is_contract_creation and tx.calldata_size > 500:
            indicators.append(ThreatIndicator(
                source="behavioral",
                category=AttackCategory.LOGIC_BUG,
                risk_weight=0.6,
                description="New contract deployment with large bytecode — possible attack contract",
                evidence=f"Contract creation, bytecode size: {tx.calldata_size} bytes",
            ))

        # Rapid multi-protocol interaction
        sender = tx.from_address
        if sender in self._recent_targets:
            recent = self._recent_targets[sender]
            unique_targets = set(recent[-10:])
            if len(unique_targets) >= 3:
                indicators.append(ThreatIndicator(
                    source="behavioral",
                    category=AttackCategory.FLASH_LOAN,
                    risk_weight=0.6,
                    description=f"Address hit {len(unique_targets)} protocols rapidly",
                    evidence=f"Recent targets: {', '.join(list(unique_targets)[:5])}",
                ))

        # Very large calldata (complex multi-step attack)
        if tx.calldata_size > 2000:
            indicators.append(ThreatIndicator(
                source="behavioral",
                category=AttackCategory.LOGIC_BUG,
                risk_weight=0.3,
                description=f"Unusually large calldata ({tx.calldata_size} bytes)",
                evidence=f"Calldata size: {tx.calldata_size} bytes (typical: <500)",
            ))

        return indicators

    def _check_attack_combos(
        self, categories: set[AttackCategory]
    ) -> list[ThreatIndicator]:
        """Detect multi-vector attack combinations that amplify risk."""
        combos = []

        # Flash loan + any manipulation = classic DeFi exploit
        if AttackCategory.FLASH_LOAN in categories:
            if AttackCategory.ORACLE_MANIPULATION in categories:
                combos.append(ThreatIndicator(
                    source="combo_analysis",
                    category=AttackCategory.FLASH_LOAN,
                    risk_weight=0.8,
                    description="CRITICAL COMBO: Flash loan + oracle manipulation — classic exploit pattern",
                    evidence="Multi-vector: flash loan funds → oracle price manipulation → profit extraction",
                    references=["Harvest Finance ($34M)", "Warp Finance ($7.7M)"],
                ))
            if AttackCategory.PRICE_MANIPULATION in categories:
                combos.append(ThreatIndicator(
                    source="combo_analysis",
                    category=AttackCategory.FLASH_LOAN,
                    risk_weight=0.75,
                    description="HIGH RISK COMBO: Flash loan + DEX price manipulation",
                    evidence="Multi-vector: flash loan → large swap → profit from price impact",
                    references=["PancakeBunny ($45M)", "bZx attacks"],
                ))
            if AttackCategory.REENTRANCY in categories:
                combos.append(ThreatIndicator(
                    source="combo_analysis",
                    category=AttackCategory.REENTRANCY,
                    risk_weight=0.85,
                    description="CRITICAL COMBO: Flash loan + reentrancy — amplified drain",
                    evidence="Multi-vector: flash loan capital → reentrant withdraw loop → amplified extraction",
                    references=["Lendf.me ($25M)", "Cream Finance"],
                ))

        # Access control + governance = insider/takeover
        if AttackCategory.ACCESS_CONTROL in categories and AttackCategory.GOVERNANCE_ATTACK in categories:
            combos.append(ThreatIndicator(
                source="combo_analysis",
                category=AttackCategory.GOVERNANCE_ATTACK,
                risk_weight=0.9,
                description="CRITICAL COMBO: Access control + governance — protocol takeover attempt",
                evidence="Multi-vector: privilege escalation → governance manipulation",
                references=["Beanstalk ($182M)"],
            ))

        return combos

    def _compute_score(self, indicators: list[ThreatIndicator]) -> float:
        """
        Composite risk score using weighted maximum with diminishing additions.
        Not a simple average — the highest-risk indicator dominates, and
        additional indicators add marginal risk.
        """
        if not indicators:
            return 0.0

        weights = sorted([i.risk_weight for i in indicators], reverse=True)

        # Highest indicator sets the base
        score = weights[0]

        # Each additional indicator adds diminishing risk
        for i, w in enumerate(weights[1:], start=1):
            diminishing_factor = 0.3 / i  # 0.3, 0.15, 0.1, ...
            score += w * diminishing_factor

        return min(1.0, score)

    @staticmethod
    def _score_to_level(score: float) -> str:
        if score >= 0.8:
            return "critical"
        if score >= 0.6:
            return "high"
        if score >= 0.4:
            return "medium"
        return "low"

    @staticmethod
    def _recommend_action(
        score: float,
        categories: set[AttackCategory],
        targets_watched: bool,
    ) -> str:
        if score >= 0.8 and targets_watched:
            return "PAUSE_CONTRACT — Autonomous emergency pause recommended"
        if score >= 0.6 and targets_watched:
            return "ALERT_AND_SIMULATE — High risk; run EVM simulation before action"
        if score >= 0.4:
            return "ALERT — Notify protocol team; continue monitoring"
        return "LOG — Record for pattern analysis"

    def _build_claude_context(
        self,
        tx: DecodedTransaction,
        indicators: list[ThreatIndicator],
        score: float,
        level: str,
    ) -> str:
        """Build a structured context string for Claude risk assessment."""
        lines = [
            "=== PROTOCOL GUARDIAN — MEMPOOL THREAT INTELLIGENCE ===",
            "",
            f"Transaction Hash: {tx.tx_hash}",
            f"From: {tx.from_address}",
            f"To: {tx.to_address or 'CONTRACT CREATION'}",
            f"Value: {tx.value_eth:.4f} ETH ({tx.value_wei} wei)",
            f"Gas Price: {tx.gas_price_gwei:.2f} gwei",
            f"Gas Limit: {tx.gas_limit:,}",
            f"Calldata Size: {tx.calldata_size} bytes",
            f"Primary Selector: {tx.input_selector or 'none'}",
            "",
            f"=== PRE-CHAIN RISK ASSESSMENT ===",
            f"Composite Risk Score: {score:.2%}",
            f"Risk Level: {level.upper()}",
            f"Threat Indicators Found: {len(indicators)}",
            "",
        ]

        if indicators:
            lines.append("=== THREAT INDICATORS ===")
            for i, ind in enumerate(indicators, 1):
                lines.append(f"  [{i}] {ind.category.value.upper()} (weight: {ind.risk_weight:.2f})")
                lines.append(f"      Source: {ind.source}")
                lines.append(f"      {ind.description}")
                lines.append(f"      Evidence: {ind.evidence}")
                if ind.references:
                    lines.append(f"      Historical precedent: {', '.join(ind.references)}")
                lines.append("")

        lines.extend([
            "=== INSTRUCTION ===",
            "Analyze this pending transaction. Assess whether the detected indicators",
            "represent a genuine exploit attempt or benign DeFi activity.",
            "Consider: (1) Are the function selectors consistent with a known attack",
            "pattern? (2) Does the combination of selectors suggest a multi-step exploit?",
            "(3) Is the gas/value behavior anomalous? (4) Should Protocol Guardian",
            "autonomously pause the target contract, or just alert the team?",
            "",
            "Respond with: risk_assessment, confidence_score, recommended_action, reasoning",
        ])

        return "\n".join(lines)

    def _track_sender(self, tx: DecodedTransaction):
        """Track sender activity for behavioral analysis."""
        sender = tx.from_address
        now = time.time()

        if sender not in self._recent_senders:
            self._recent_senders[sender] = []
            self._recent_targets[sender] = []

        self._recent_senders[sender].append(now)
        if tx.to_address:
            self._recent_targets[sender].append(tx.to_address)

        # Keep only last 60 seconds of history
        cutoff = now - 60
        self._recent_senders[sender] = [
            t for t in self._recent_senders[sender] if t > cutoff
        ]
        self._recent_targets[sender] = self._recent_targets[sender][-20:]
