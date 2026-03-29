"""
heuristics.py — Fast pre-filter before the expensive AI reasoning call.

Checks transaction context against known DeFi attack patterns.
Returns a HeuristicsResult that tells the AI agent what to focus on.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("guardian.heuristics")

# Known dangerous function selectors
FLASH_LOAN_SELECTORS = {
    "0xab9c4b5d": "flashLoan(address,uint256,bytes)",
    "0x5cffe9de": "flashLoan(address,address,uint256,uint256,bytes)",
    "0x42b0b77c": "flashLoanSimple(address,uint256,bytes,uint16)",
    "0xd9d98ce4": "flash(address,uint256,uint256,bytes)",
    "0xe8eda9df": "deposit(address,uint256,address,uint16)",
}

DANGEROUS_SELECTORS = {
    "0x40c10f19": "mint(address,uint256) — ERC20 mint",
    "0x9dc29fac": "burn(address,uint256) — ERC20 burn",
    "0x2f745c59": "tokenOfOwnerByIndex — common in NFT exploits",
}

PRICE_UPDATE_SELECTORS = {
    "0x8a0dac4a": "setPrice(uint256)",
    "0x00e4768b": "updatePrice(uint256)",
    "0x7e2d5753": "setAnswer(int256)",
}

LARGE_ETH_THRESHOLD_WEI = int(0.05 * 10**18)  # 0.05 ETH (lowered for Sepolia demo)
PRICE_DEVIATION_THRESHOLD = 0.05  # 5% move in one tx
BALANCE_DRAIN_THRESHOLD = 0.20   # 20% balance drop


@dataclass
class Signal:
    name: str
    severity: str  # "critical", "high", "medium"
    description: str
    raw_data: Optional[dict] = None


@dataclass
class HeuristicsResult:
    """
    Output of the heuristics engine.
    If should_escalate=True, the AI agent is invoked.
    """
    should_escalate: bool
    signals: List[Signal] = field(default_factory=list)
    risk_score: int = 0   # 0-100, rough pre-AI estimate
    summary: str = ""

    def add_signal(self, signal: Signal):
        self.signals.append(signal)
        weights = {"critical": 40, "high": 25, "medium": 10}
        self.risk_score = min(100, self.risk_score + weights.get(signal.severity, 5))
        if self.risk_score >= 30:
            self.should_escalate = True

    def to_prompt_context(self) -> str:
        """Serialise signals into a concise string for the AI prompt."""
        lines = [f"Pre-screening risk score: {self.risk_score}/100"]
        for s in self.signals:
            lines.append(f"  [{s.severity.upper()}] {s.name}: {s.description}")
        return "\n".join(lines)


class HeuristicsEngine:
    """
    Stateless fast-path screener. Called on every interesting transaction
    before the AI agent is invoked.
    """

    def analyse(self, ctx) -> HeuristicsResult:
        """
        ctx: TxContext from ingestion.py
        Returns HeuristicsResult.
        """
        result = HeuristicsResult(should_escalate=False)

        self._check_flash_loan(ctx, result)
        self._check_large_value(ctx, result)
        self._check_price_manipulation(ctx, result)
        self._check_balance_drain(ctx, result)
        self._check_dangerous_selectors(ctx, result)

        # Build summary
        if result.signals:
            names = [s.name for s in result.signals]
            result.summary = f"Detected signals: {', '.join(names)}. Risk score: {result.risk_score}/100"
            logger.info(f"Heuristics [{ctx.tx_hash[:10]}]: {result.summary}")
        else:
            result.summary = "No signals detected"

        return result

    def _check_flash_loan(self, ctx, result: HeuristicsResult):
        input_data = ctx.input_data or "0x"
        selector = input_data[:10].lower() if len(input_data) >= 10 else ""

        if ctx.is_flash_loan or selector in FLASH_LOAN_SELECTORS:
            fn_name = FLASH_LOAN_SELECTORS.get(selector, "unknown flashLoan variant")
            result.add_signal(Signal(
                name="flash_loan_detected",
                severity="high",
                description=f"Flash loan call detected: {fn_name}. Selector: {selector}",
                raw_data={"selector": selector, "fn": fn_name}
            ))

    def _check_large_value(self, ctx, result: HeuristicsResult):
        value = ctx.value_wei or 0
        if value >= LARGE_ETH_THRESHOLD_WEI:
            eth_val = value / 10**18
            result.add_signal(Signal(
                name="large_value_transfer",
                severity="medium",
                description=f"Large ETH transfer: {eth_val:.4f} ETH",
                raw_data={"value_wei": value, "value_eth": eth_val}
            ))

    def _check_price_manipulation(self, ctx, result: HeuristicsResult):
        if ctx.price_before and ctx.price_after:
            change = abs(ctx.price_after - ctx.price_before) / max(ctx.price_before, 1)
            if change >= PRICE_DEVIATION_THRESHOLD:
                result.add_signal(Signal(
                    name="oracle_price_manipulation",
                    severity="critical",
                    description=f"Oracle price moved {change*100:.1f}% in single tx: {ctx.price_before} -> {ctx.price_after}",
                    raw_data={"price_before": ctx.price_before, "price_after": ctx.price_after, "change_pct": change * 100}
                ))

        # Also check if this tx calls a price update function
        input_data = ctx.input_data or "0x"
        selector = input_data[:10].lower() if len(input_data) >= 10 else ""
        if selector in PRICE_UPDATE_SELECTORS:
            fn_name = PRICE_UPDATE_SELECTORS[selector]
            result.add_signal(Signal(
                name="price_oracle_update",
                severity="high",
                description=f"Price oracle update call: {fn_name}. May precede manipulation.",
                raw_data={"selector": selector}
            ))

    def _check_balance_drain(self, ctx, result: HeuristicsResult):
        if ctx.pool_balance_before and ctx.pool_balance_after:
            before = ctx.pool_balance_before
            after = ctx.pool_balance_after
            if before > 0:
                drain = (before - after) / before
                if drain >= BALANCE_DRAIN_THRESHOLD:
                    result.add_signal(Signal(
                        name="pool_balance_drain",
                        severity="critical",
                        description=f"Pool balance drained {drain*100:.1f}%: {before/1e18:.4f} ETH -> {after/1e18:.4f} ETH",
                        raw_data={"before_wei": before, "after_wei": after, "drain_pct": drain * 100}
                    ))

    def _check_dangerous_selectors(self, ctx, result: HeuristicsResult):
        input_data = ctx.input_data or "0x"
        selector = input_data[:10].lower() if len(input_data) >= 10 else ""
        if selector in DANGEROUS_SELECTORS:
            fn_name = DANGEROUS_SELECTORS[selector]
            result.add_signal(Signal(
                name="dangerous_function_call",
                severity="high",
                description=f"Dangerous function call detected: {fn_name}",
                raw_data={"selector": selector, "fn": fn_name}
            ))
