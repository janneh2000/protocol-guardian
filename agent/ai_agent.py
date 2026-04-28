"""
ai_agent.py — AI reasoning layer using Claude Opus.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

import anthropic
from .exploit_rag import ExploitRAG
from .keeperhub_bridge import fetch_paid_intel, reconcile_with_intel
from .axl import broadcast_threat, recv_peer_threats

logger = logging.getLogger("guardian.ai_agent")


@dataclass
class AgentDecision:
    attack_type: str
    confidence: int
    action: str
    suspected_attacker: str
    estimated_loss_usd: int
    rationale: str
    raw_response: str


SYSTEM_PROMPT = """You are Protocol Guardian, an autonomous DeFi security AI agent.

Your job is to analyse suspicious Ethereum transactions and determine if a protocol is under attack.
You have deep knowledge of DeFi exploit patterns including:
- Flash loan price manipulation attacks
- Reentrancy exploits
- Oracle manipulation
- Governance attacks
- Access control exploits
- Sandwich attacks
- MEV extraction

You will receive:
1. Transaction data (hash, from, to, value, input data/selector)
2. Pre-screening signals from the heuristics engine
3. Similar historical exploits from our exploit database
4. Current pool state

You MUST respond with ONLY valid JSON in this exact format:
{
  "attack_type": "<snake_case attack classification or 'benign'>",
  "confidence": <integer 0-100>,
  "action": "<PAUSE|ALERT|IGNORE>",
  "suspected_attacker": "<0x address or 'unknown'>",
  "estimated_loss_usd": <integer, 0 if unknown>,
  "rationale": "<2-4 sentence plain-English explanation of your reasoning>"
}

Action decision rules:
- PAUSE: confidence >= 75. Use when funds are clearly at imminent risk.
- ALERT: confidence 40-74. Suspicious but not certain enough to pause.
- IGNORE: confidence < 40. Likely benign.

Be conservative — a false positive (unnecessary pause) is bad, but a missed exploit (funds drained) is catastrophic.
Your rationale should be detailed enough to explain to a protocol team WHY you took action."""


class AIAgent:
    def __init__(self, api_key: str, pool_address: str, pool_abi_path: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.pool_address = pool_address
        self.rag = ExploitRAG()
        self.model = "claude-opus-4-5"

    async def analyse(self, ctx, heuristics_result) -> AgentDecision:
        # ── AXL swarm pre-check ─────────────────────────────────────────
        # Before classifying, pull any peer Guardians' threat fingerprints
        # off our local AXL node. If a peer has just paused on a tx that
        # matches THIS tx's selector + target, we already have strong prior
        # evidence; we record the peer signal and let it amplify Claude's
        # confidence in the merge step below.
        peer_signal_confidence = 0
        try:
            for fp in await recv_peer_threats():
                if fp.matches_tx(
                    ctx.input_data[:10] if len(ctx.input_data or "") >= 10 else "0x",
                    ctx.to_addr or "0x",
                ):
                    peer_signal_confidence = max(peer_signal_confidence, fp.confidence)
            if peer_signal_confidence:
                logger.info(
                    f"AXL peer prior for {ctx.tx_hash[:16]}: confidence={peer_signal_confidence}"
                )
        except Exception as e:
            logger.debug(f"AXL pre-check failed (continuing): {e}")

        similar_exploits = self.rag.get_similar_exploits(
            signals=[s.name for s in heuristics_result.signals],
            input_selector=ctx.input_data[:10] if len(ctx.input_data or "") >= 10 else ""
        )
        user_message = self._build_prompt(ctx, heuristics_result, similar_exploits)
        logger.info(f"Invoking Claude Opus for tx: {ctx.tx_hash[:16]}...")

        response = self.client.messages.create(
            model=self.model,
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )

        raw_response = response.content[0].text
        decision = self._parse_response(raw_response, ctx.tx_hash)
        logger.info(f"Decision for {ctx.tx_hash[:16]}: {decision.action} | {decision.attack_type} | confidence={decision.confidence}%")

        # ── KeeperHub paid-intel escalation ─────────────────────────────
        # When confidence sits in the ALERT band (40-74) we pay an x402-gated
        # threat-intel feed via @keeperhub/wallet's paymentSigner to disambiguate.
        # The PreToolUse safety hook gates anything above the auto-approve floor.
        if 40 <= decision.confidence <= 74 and ctx.input_data:
            selector = ctx.input_data[:10] if len(ctx.input_data) >= 10 else "0x"
            target = ctx.to_addr or "0x"
            logger.info(f"ALERT band — escalating to KeeperHub-paid threat intel ({selector} on {target})")
            intel = await fetch_paid_intel(selector, target)
            if intel.get("ok"):
                merged = reconcile_with_intel({
                    "confidence": decision.confidence,
                    "action": decision.action,
                    "rationale": decision.rationale,
                }, intel)
                if merged["action"] != decision.action:
                    logger.info(
                        f"KeeperHub intel changed decision: {decision.action} -> {merged['action']} "
                        f"(confidence {decision.confidence} -> {merged['confidence']})"
                    )
                    decision.confidence = merged["confidence"]
                    decision.action = merged["action"]
                    decision.rationale = merged["rationale"]
            else:
                logger.debug(f"KeeperHub intel unavailable: {intel.get('error')}")

        # ── AXL swarm broadcast ─────────────────────────────────────────
        # If we landed on PAUSE, fan the threat fingerprint out to every
        # peer Guardian over our local AXL node. Failure is non-fatal —
        # the action layer still pauses on-chain even if the swarm is down.
        if decision.action == "PAUSE" and ctx.input_data and ctx.to_addr:
            try:
                selector = ctx.input_data[:10] if len(ctx.input_data) >= 10 else "0x"
                await broadcast_threat(
                    function_selector=selector,
                    target_address=ctx.to_addr,
                    confidence=decision.confidence,
                )
            except Exception as e:
                logger.debug(f"AXL broadcast failed (non-fatal): {e}")

        # If a peer signal exceeded the threshold and Claude was wishy-washy,
        # let the peer signal amplify the local decision (capped at 80).
        if peer_signal_confidence >= 75 and decision.action == "ALERT":
            new_conf = min(80, max(decision.confidence, peer_signal_confidence))
            logger.info(
                f"AXL peer prior amplified ALERT → PAUSE for {ctx.tx_hash[:16]}: "
                f"confidence {decision.confidence} → {new_conf}"
            )
            decision.confidence = new_conf
            decision.action = "PAUSE"
            decision.rationale = (
                decision.rationale + " [Confirmed by peer Guardian over Gensyn AXL.]"
            ).strip()

        return decision

    def _build_prompt(self, ctx, heuristics, similar_exploits: list) -> str:
        lines = [
            "=== TRANSACTION UNDER ANALYSIS ===",
            f"Hash:        {ctx.tx_hash}",
            f"From:        {ctx.from_addr}",
            f"To:          {ctx.to_addr}",
            f"Value:       {ctx.value_wei / 1e18:.6f} ETH",
            f"Input data:  {ctx.input_data[:100]}{'...' if len(ctx.input_data or '') > 100 else ''}",
            f"Source:      {'mempool (pre-confirmation)' if not ctx.block_number else f'block {ctx.block_number}'}",
            "",
            "=== POOL STATE ===",
            f"Monitored protocol: {self.pool_address}",
            f"Pool balance before: {(ctx.pool_balance_before or 0) / 1e18:.6f} ETH",
            f"Pool balance after:  {(ctx.pool_balance_after or 0) / 1e18:.6f} ETH",
            f"Oracle price before: ${(ctx.price_before or 0) / 1e18:,.2f}",
            f"Oracle price after:  ${(ctx.price_after or 0) / 1e18:,.2f}",
            "",
            "=== HEURISTICS PRE-SCREENING ===",
            heuristics.to_prompt_context(),
            "",
        ]
        if similar_exploits:
            lines.append("=== SIMILAR HISTORICAL EXPLOITS (RAG) ===")
            for ex in similar_exploits[:3]:
                lines.append(f"- {ex['name']} ({ex['date']}): {ex['description']} [Loss: ${ex.get('loss_usd', 'unknown'):,}]")
            lines.append("")
        lines.append("Analyse this transaction and respond with your JSON decision.")
        return "\n".join(lines)

    def _parse_response(self, raw: str, tx_hash: str) -> AgentDecision:
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip()
        try:
            data = json.loads(clean)
            return AgentDecision(
                attack_type=data.get("attack_type", "unknown"),
                confidence=int(data.get("confidence", 0)),
                action=data.get("action", "IGNORE").upper(),
                suspected_attacker=data.get("suspected_attacker", "unknown"),
                estimated_loss_usd=int(data.get("estimated_loss_usd", 0)),
                rationale=data.get("rationale", ""),
                raw_response=raw,
            )
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error(f"Failed to parse Claude response for {tx_hash}: {e}")
            return AgentDecision(
                attack_type="parse_error", confidence=0, action="ALERT",
                suspected_attacker="unknown", estimated_loss_usd=0,
                rationale=f"AI response parse error. Manual review required. Raw: {raw[:200]}",
                raw_response=raw,
            )
