import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent / ".env")

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(Path(__file__).parent / "guardian.log"),
    ],
)
logger = logging.getLogger("guardian.main")
logging.getLogger("web3").setLevel(logging.WARNING)
logging.getLogger("websockets").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)

from agent.ingestion import BlockchainIngestion
from agent.heuristics import HeuristicsEngine

# ── Protocol Guardian v2: Mempool + RAG imports ──
from mempool.api import MempoolAPI, setup_mempool_routes
from knowledge.exploit_db import ExploitKnowledgeBase


def _write_to_supabase(result: dict):
    """Write event directly to Supabase — works in both real and simulate mode."""
    try:
        url = os.getenv("SUPABASE_URL", "").strip()
        key = os.getenv("SUPABASE_KEY", "").strip()
        if not url or not key:
            return
        from supabase import create_client
        sb = create_client(url, key)
        sb.table("events").insert({
            "tx_hash":            result.get("tx_hash", ""),
            "action":             result.get("action", ""),
            "attack_type":        result.get("attack_type", ""),
            "confidence":         int(result.get("confidence", 0)),
            "rationale":          result.get("rationale", ""),
            "estimated_loss_usd": int(result.get("estimated_loss_usd", 0)),
            "suspected_attacker": result.get("suspected_attacker", "unknown"),
            "pause_tx_hash":      result.get("pause_tx_hash"),
            "success":            bool(result.get("success", False)),
        }).execute()
        logger.info("Event synced to Supabase dashboard")
    except Exception as e:
        logger.warning(f"Supabase write error: {e}")


class ProtocolGuardianAgent:
    def __init__(self, simulate: bool = False, no_ai: bool = False):
        self.simulate = simulate
        self.no_ai = no_ai
        self._validate_env()

        self.heuristics = HeuristicsEngine()

        # ── v2: Initialize RAG exploit knowledge base ──
        self.knowledge_base = ExploitKnowledgeBase()
        kb_stats = self.knowledge_base.get_stats()
        logger.info(
            f"RAG Knowledge Base loaded: {kb_stats['total_exploits']} exploits, "
            f"{kb_stats['total_loss_display']} total losses"
        )

        # ── v2: Mempool API (will be started in run()) ──
        self.mempool_api = None

        if not no_ai:
            from agent.ai_agent import AIAgent
            self.ai_agent = AIAgent(
                api_key=os.environ["ANTHROPIC_API_KEY"],
                pool_address=os.environ["LENDING_POOL_ADDRESS"],
                pool_abi_path=str(Path(__file__).parent / "abi" / "MockLendingPool.json"),
            )
        else:
            self.ai_agent = None

        if not simulate:
            from agent.action import ActionLayer
            self.action = ActionLayer(
                rpc_url=os.environ["ALCHEMY_HTTP_RPC"],
                guardian_contract_address=os.environ["GUARDIAN_CONTRACT_ADDRESS"],
                guardian_abi_path=str(Path(__file__).parent / "abi" / "ProtocolGuardian.json"),
                hot_wallet_private_key=os.environ["GUARDIAN_HOT_WALLET_PRIVATE_KEY"],
                discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL"),
                telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN"),
                telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID"),
            )
        else:
            self.action = None

        self.ingestion = BlockchainIngestion(
            ws_rpc_url=os.environ["ALCHEMY_WS_RPC"],
            pool_address=os.environ["LENDING_POOL_ADDRESS"],
            on_suspicious_tx=self._on_suspicious_tx,
        )
        self.processed_hashes = set()

    def _validate_env(self):
        required = [
            "ALCHEMY_WS_RPC", "ALCHEMY_HTTP_RPC", "LENDING_POOL_ADDRESS",
        ]
        if not self.no_ai:
            required.append("ANTHROPIC_API_KEY")
        if not self.simulate:
            required += ["GUARDIAN_CONTRACT_ADDRESS", "GUARDIAN_HOT_WALLET_PRIVATE_KEY"]

        missing = [k for k in required if not os.getenv(k)]
        if missing:
            logger.error(f"Missing required environment variables: {missing}")
            sys.exit(1)

    async def _on_suspicious_tx(self, ctx, source: str):
        if ctx.tx_hash in self.processed_hashes:
            return
        self.processed_hashes.add(ctx.tx_hash)
        if len(self.processed_hashes) > 1000:
            self.processed_hashes = set(list(self.processed_hashes)[-500:])

        logger.info(f"[{source}] Analysing tx: {ctx.tx_hash[:18]}...")

        # 1. Heuristics (always runs)
        heuristics_result = self.heuristics.analyse(ctx)
        if not heuristics_result.should_escalate:
            return

        logger.info(f"Heuristics escalation — risk={heuristics_result.risk_score} | {heuristics_result.summary}")

        # ── v2: RAG context enrichment ──
        # Query the exploit knowledge base for historical parallels
        rag_context = ""
        try:
            # Extract attack categories from heuristics
            detected_categories = []
            summary_lower = heuristics_result.summary.lower()
            if "flash" in summary_lower:
                detected_categories.append("flash_loan")
            if "reentr" in summary_lower:
                detected_categories.append("reentrancy")
            if "oracle" in summary_lower or "price" in summary_lower:
                detected_categories.append("oracle_manipulation")
            if "access" in summary_lower or "owner" in summary_lower:
                detected_categories.append("access_control")
            if "govern" in summary_lower:
                detected_categories.append("governance_attack")

            if detected_categories:
                rag_context = self.knowledge_base.get_context_for_threat(
                    categories=detected_categories,
                    selectors=[],  # Can extract from ctx.input_data if available
                    max_exploits=3,
                )
                logger.info(f"RAG enrichment: found historical parallels for {detected_categories}")
        except Exception as e:
            logger.warning(f"RAG context error: {e}")

        # 2. AI reasoning (skipped if --no-ai)
        if self.ai_agent:
            # ── v2: Inject RAG context into AI analysis ──
            decision = await self.ai_agent.analyse(ctx, heuristics_result, rag_context=rag_context)
        else:
            # Mock decision for no-ai mode
            from agent.ai_agent import AgentDecision
            decision = AgentDecision(
                attack_type="flash_loan_price_manipulation",
                confidence=85,
                action="PAUSE",
                suspected_attacker=ctx.from_addr,
                estimated_loss_usd=42000,
                rationale=f"[MOCK] Heuristics detected: {heuristics_result.summary}. Simulated AI decision.",
                raw_response="mock",
            )

        logger.info(f"Decision: {decision.action} | {decision.attack_type} | confidence={decision.confidence}%")

        # 3. Execute (or simulate)
        if not self.simulate:
            result = await self.action.execute(ctx, decision)
        else:
            result = {
                "tx_hash": ctx.tx_hash,
                "action": decision.action,
                "attack_type": decision.attack_type,
                "confidence": decision.confidence,
                "rationale": decision.rationale,
                "suspected_attacker": decision.suspected_attacker,
                "estimated_loss_usd": decision.estimated_loss_usd,
                "pause_tx_hash": None,
                "success": True,
                "simulated": True,
            }
            logger.info(f"[SIMULATE] Would execute: {decision.action} — writing to dashboard anyway")
            # Write to Supabase even in simulate mode so dashboard shows data
            _write_to_supabase(result)

        # 4. Post-incident report if pause
        if decision.action == "PAUSE" and self.ai_agent:
            from agent.report import ReportGenerator
            reporter = ReportGenerator(api_key=os.environ["ANTHROPIC_API_KEY"])
            report = await reporter.generate(ctx, decision, result)
            report_path = Path(__file__).parent / "dashboard" / "last_report.json"
            import json
            report_path.write_text(json.dumps(report, indent=2))
            if not self.simulate and self.action:
                self.action.write_report_to_supabase(report)
            else:
                try:
                    url = os.getenv("SUPABASE_URL", "").strip()
                    key = os.getenv("SUPABASE_KEY", "").strip()
                    if url and key:
                        from supabase import create_client
                        sb = create_client(url, key)
                        sb.table("reports").insert({"data": report}).execute()
                except Exception as e:
                    logger.warning(f"Report Supabase write error: {e}")

    async def run(self):
        mode = "SIMULATE" if self.simulate else "LIVE"
        ai = "NO-AI (mock decisions)" if self.no_ai else "Claude AI"
        print(f"""
╔══════════════════════════════════════════════════════════════════╗
║     Protocol Guardian v2 — {mode:<18}                       ║
╠══════════════════════════════════════════════════════════════════╣
║  Ingestion  → HTTP block polling (3s) + Mempool pre-tx monitor  ║
║  Heuristics → Flash loan, drain, oracle, reentrancy checks      ║
║  RAG Engine → {self.knowledge_base.get_stats()['total_exploits']} exploits / {self.knowledge_base.get_stats()['total_loss_display']} historical context       ║
║  AI Layer   → {ai:<36}                  ║
║  Action     → {"Onchain emergencyPause()" if not self.simulate else "Simulate only (writes to dashboard)  "}   ║
╚══════════════════════════════════════════════════════════════════╝
""")
        logger.info(f"Pool:     {os.environ.get('LENDING_POOL_ADDRESS')}")
        logger.info(f"Guardian: {os.environ.get('GUARDIAN_CONTRACT_ADDRESS', 'N/A')}")
        logger.info(f"Supabase: {'configured' if os.getenv('SUPABASE_URL') else 'NOT configured — dashboard will be empty'}")

        # ── v2: Start mempool monitor in background ──
        ws_url = os.getenv("ALCHEMY_WS_RPC", "")
        http_url = os.getenv("ALCHEMY_HTTP_RPC", "")
        pool_addr = os.environ["LENDING_POOL_ADDRESS"]
        guardian_addr = os.getenv("GUARDIAN_CONTRACT_ADDRESS", "")
        watched = [addr for addr in [pool_addr, guardian_addr] if addr]

        try:
            from mempool.monitor import create_monitor
            monitor = create_monitor(
                ws_url=ws_url,
                http_url=http_url,
                watched_contracts=watched,
                use_enhanced=True,
            )
            # Wire threat callbacks
            async def on_mempool_threat(report):
                logger.warning(
                    f"[MEMPOOL] Pre-tx threat: score={report.composite_risk_score:.0%} "
                    f"level={report.risk_level} cats={report.attack_categories} "
                    f"tx={report.tx.tx_hash[:16]}..."
                )
                # Write mempool threats to Supabase for dashboard
                _write_to_supabase({
                    "tx_hash": report.tx.tx_hash,
                    "action": report.recommended_action,
                    "attack_type": ",".join(report.attack_categories),
                    "confidence": int(report.composite_risk_score * 100),
                    "rationale": f"[MEMPOOL PRE-TX] {len(report.indicators)} indicators detected before block confirmation",
                    "estimated_loss_usd": 0,
                    "suspected_attacker": report.tx.from_address,
                    "pause_tx_hash": None,
                    "success": True,
                })

            async def on_mempool_critical(report):
                logger.critical(
                    f"[MEMPOOL CRITICAL] Autonomous pause recommended! "
                    f"score={report.composite_risk_score:.0%} tx={report.tx.tx_hash[:16]}..."
                )

            monitor.on_threat(on_mempool_threat)
            monitor.on_critical(on_mempool_critical)

            logger.info(f"Mempool monitor starting — watching {len(watched)} contracts")
            asyncio.create_task(monitor.start())
        except Exception as e:
            logger.warning(f"Mempool monitor failed to start: {e} — continuing with block-level monitoring only")

        # Start original block-level ingestion
        await self.ingestion.start()


def main():
    simulate = "--simulate" in sys.argv
    no_ai    = "--no-ai"    in sys.argv
    agent = ProtocolGuardianAgent(simulate=simulate, no_ai=no_ai)
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Guardian stopped")


if __name__ == "__main__":
    main()