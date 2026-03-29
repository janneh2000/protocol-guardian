"""
main.py — Protocol Guardian Agent entry point.

Orchestrates: Ingestion → Heuristics → AI Agent → Action → Report

Usage:
    python main.py              # Run the full guardian agent
    python main.py --simulate   # Dry-run without onchain transactions
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")

# Configure logging
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(Path(__file__).parent.parent / "guardian.log"),
    ],
)
logger = logging.getLogger("guardian.main")

# Suppress noisy libs
logging.getLogger("web3").setLevel(logging.WARNING)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

from agent.ingestion import BlockchainIngestion
from agent.heuristics import HeuristicsEngine
from agent.ai_agent import AIAgent
from agent.action import ActionLayer
from agent.report import ReportGenerator


class ProtocolGuardianAgent:
    def __init__(self, simulate: bool = False):
        self.simulate = simulate
        self._validate_env()

        self.heuristics = HeuristicsEngine()

        self.ai_agent = AIAgent(
            api_key=os.environ["ANTHROPIC_API_KEY"],
            pool_address=os.environ["LENDING_POOL_ADDRESS"],
            pool_abi_path=str(Path(__file__).parent.parent / "abi" / "MockLendingPool.json"),
        )

        if not simulate:
            self.action = ActionLayer(
                rpc_url=os.environ["ALCHEMY_HTTP_RPC"],
                guardian_contract_address=os.environ["GUARDIAN_CONTRACT_ADDRESS"],
                guardian_abi_path=str(Path(__file__).parent.parent / "abi" / "ProtocolGuardian.json"),
                hot_wallet_private_key=os.environ["GUARDIAN_HOT_WALLET_PRIVATE_KEY"],
                discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL"),
                telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
                telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
            )
        else:
            self.action = None
            logger.info("Running in SIMULATE mode — no onchain transactions will be sent")

        self.reporter = ReportGenerator(api_key=os.environ["ANTHROPIC_API_KEY"])

        self.ingestion = BlockchainIngestion(
            ws_rpc_url=os.environ["ALCHEMY_WS_RPC"],
            pool_address=os.environ["LENDING_POOL_ADDRESS"],
            on_suspicious_tx=self._on_suspicious_tx,
        )

        self.processed_hashes = set()  # deduplicate

    def _validate_env(self):
        required = [
            "ANTHROPIC_API_KEY",
            "ALCHEMY_WS_RPC",
            "ALCHEMY_HTTP_RPC",
            "LENDING_POOL_ADDRESS",
        ]
        if not self.simulate:
            required += ["GUARDIAN_CONTRACT_ADDRESS", "GUARDIAN_HOT_WALLET_PRIVATE_KEY"]

        missing = [k for k in required if not os.getenv(k)]
        if missing:
            logger.error(f"Missing required environment variables: {missing}")
            logger.error("Copy .env.example to .env and fill in all values")
            sys.exit(1)

    async def _on_suspicious_tx(self, ctx, source: str):
        """Callback from ingestion layer — full analysis pipeline."""
        # Deduplicate
        if ctx.tx_hash in self.processed_hashes:
            return
        self.processed_hashes.add(ctx.tx_hash)
        # Trim dedupe set
        if len(self.processed_hashes) > 1000:
            self.processed_hashes = set(list(self.processed_hashes)[-500:])

        logger.info(f"[{source}] Analysing tx: {ctx.tx_hash[:16]}...")

        # 1. Heuristics
        heuristics_result = self.heuristics.analyse(ctx)

        if not heuristics_result.should_escalate:
            logger.debug(f"Heuristics: no escalation needed for {ctx.tx_hash[:16]}")
            return

        logger.info(f"Heuristics escalation — risk_score={heuristics_result.risk_score} | {heuristics_result.summary}")

        # 2. AI reasoning
        decision = await self.ai_agent.analyse(ctx, heuristics_result)

        logger.info(
            f"AI decision: {decision.action} | {decision.attack_type} | "
            f"confidence={decision.confidence}% | {decision.rationale[:80]}..."
        )

        # 3. Execute action
        if self.simulate:
            logger.info(f"[SIMULATE] Would execute: {decision.action}")
            result = {
                "action": decision.action,
                "attack_type": decision.attack_type,
                "confidence": decision.confidence,
                "rationale": decision.rationale,
                "simulated": True,
            }
        else:
            result = await self.action.execute(ctx, decision)

        # 4. Generate post-incident report if pause fired
        if decision.action == "PAUSE":
            report = await self.reporter.generate(ctx, decision, result)
            # Save report
            report_path = Path(__file__).parent.parent / "dashboard" / "last_report.json"
            import json
            report_path.write_text(json.dumps(report, indent=2))
            logger.info(f"Post-incident report saved to {report_path}")

    async def run(self):
        banner = """
╔══════════════════════════════════════════════════╗
║     Protocol Guardian Agent — Starting Up        ║
╠══════════════════════════════════════════════════╣
║  Ingestion  → WebSocket mempool + block stream   ║
║  Heuristics → Flash loan, drain, oracle checks   ║
║  AI Layer   → Claude threat classification       ║
║  Action     → Onchain emergencyPause()           ║
║  Reports    → Auto-generated incident reports    ║
╚══════════════════════════════════════════════════╝
"""
        print(banner)
        logger.info(f"Monitoring pool: {os.environ.get('LENDING_POOL_ADDRESS')}")
        logger.info(f"Guardian contract: {os.environ.get('GUARDIAN_CONTRACT_ADDRESS', 'N/A (simulate mode)')}")
        logger.info(f"Simulate mode: {self.simulate}")

        await self.ingestion.start()


def main():
    simulate = "--simulate" in sys.argv
    agent = ProtocolGuardianAgent(simulate=simulate)
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Guardian agent stopped by user")


if __name__ == "__main__":
    main()
