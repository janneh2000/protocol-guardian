"""
action.py — Executes the AI agent's decision onchain.

Handles:
  - Calling emergencyPause() on the GuardianController contract
  - Sending Discord / Telegram alerts
  - Writing events to local JSON + Supabase (for live Vercel dashboard)
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiohttp
from web3 import Web3

logger = logging.getLogger("guardian.action")

EVENTS_LOG_PATH = Path(__file__).parent.parent / "dashboard" / "events.json"


def _get_supabase():
    """Lazily create Supabase client — returns None if not configured."""
    url = os.getenv("SUPABASE_URL", "").strip()
    key = os.getenv("SUPABASE_KEY", "").strip()
    if not url or not key:
        return None
    try:
        from supabase import create_client
        return create_client(url, key)
    except ImportError:
        logger.warning("supabase package not installed. Run: pip3 install supabase")
        return None
    except Exception as e:
        logger.warning(f"Supabase client error: {e}")
        return None


class ActionLayer:
    def __init__(
        self,
        rpc_url: str,
        guardian_contract_address: str,
        guardian_abi_path: str,
        hot_wallet_private_key: str,
        discord_webhook_url: Optional[str] = None,
        telegram_bot_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.guardian_address = Web3.to_checksum_address(guardian_contract_address)
        self.discord_webhook = discord_webhook_url
        self.telegram_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id

        with open(guardian_abi_path) as f:
            abi = json.load(f)
        self.guardian_contract = self.w3.eth.contract(
            address=self.guardian_address, abi=abi
        )

        self.account = self.w3.eth.account.from_key(hot_wallet_private_key)
        logger.info(f"Action layer ready. Hot wallet: {self.account.address}")
        logger.info(f"Guardian contract: {self.guardian_address}")

        EVENTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not EVENTS_LOG_PATH.exists():
            EVENTS_LOG_PATH.write_text("[]")

        sb = _get_supabase()
        if sb:
            logger.info("Supabase connected — events will sync to live dashboard")
        else:
            logger.info("Supabase not configured — events saved locally only")

    async def execute(self, ctx, decision) -> dict:
        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tx_hash": ctx.tx_hash,
            "from": ctx.from_addr,
            "action": decision.action,
            "attack_type": decision.attack_type,
            "confidence": decision.confidence,
            "suspected_attacker": decision.suspected_attacker,
            "estimated_loss_usd": decision.estimated_loss_usd,
            "rationale": decision.rationale,
            "pause_tx_hash": None,
            "success": False,
        }

        if decision.action == "PAUSE":
            pause_result = await self._execute_pause(decision, ctx)
            result.update(pause_result)
            await self._send_alert(result, level="critical")

        elif decision.action == "ALERT":
            logger.warning(
                f"ALERT [{decision.attack_type}] confidence={decision.confidence}% | {decision.rationale}"
            )
            await self._send_alert(result, level="warning")
            result["success"] = True

        else:
            logger.debug(f"IGNORE: {decision.rationale}")
            result["success"] = True

        self._append_event(result)
        return result

    async def _execute_pause(self, decision, ctx) -> dict:
        logger.critical(
            f"PAUSING PROTOCOL — {decision.attack_type} | "
            f"confidence={decision.confidence}% | attacker={decision.suspected_attacker}"
        )
        try:
            nonce = self.w3.eth.get_transaction_count(self.account.address)
            gas_price = self.w3.eth.gas_price
            rationale = decision.rationale[:500]
            attacker = (
                Web3.to_checksum_address(decision.suspected_attacker)
                if decision.suspected_attacker.startswith("0x") and len(decision.suspected_attacker) == 42
                else "0x0000000000000000000000000000000000000000"
            )

            txn = self.guardian_contract.functions.emergencyPause(
                decision.attack_type[:64],
                decision.confidence,
                attacker,
                decision.estimated_loss_usd,
                rationale,
            ).build_transaction({
                "from": self.account.address,
                "nonce": nonce,
                "gasPrice": gas_price,
                "gas": 300000,
            })

            signed = self.w3.eth.account.sign_transaction(txn, self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            tx_hash_hex = "0x" + tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash
            logger.critical(f"Pause tx submitted: {tx_hash_hex}")

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            success = receipt.status == 1

            if success:
                logger.critical(f"PROTOCOL PAUSED. Block: {receipt.blockNumber} | Tx: {tx_hash_hex}")
            else:
                logger.error(f"Pause tx FAILED (reverted). Tx: {tx_hash_hex}")

            return {"pause_tx_hash": tx_hash_hex, "pause_block": receipt.blockNumber, "success": success}

        except Exception as e:
            logger.error(f"Failed to execute pause: {e}", exc_info=True)
            return {"pause_tx_hash": None, "success": False, "error": str(e)}

    async def _send_alert(self, result: dict, level: str):
        message = self._format_alert(result, level)
        tasks = []
        if self.discord_webhook:
            tasks.append(self._send_discord(message, level))
        if self.telegram_token and self.telegram_chat_id:
            tasks.append(self._send_telegram(message))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _format_alert(self, result: dict, level: str) -> str:
        icon = "PAUSE" if level == "critical" else "ALERT"
        lines = [
            f"[{icon}] Protocol Guardian",
            f"Attack: {result['attack_type']}",
            f"Confidence: {result['confidence']}%",
            f"Attacker: {result['suspected_attacker']}",
            f"Risk: ${result['estimated_loss_usd']:,}",
            f"Reason: {result['rationale']}",
            f"Tx: {result['tx_hash']}",
        ]
        if result.get("pause_tx_hash"):
            lines.append(f"Pause tx: {result['pause_tx_hash']}")
        return "\n".join(lines)

    async def _send_discord(self, message: str, level: str):
        try:
            color = 0xFF0000 if level == "critical" else 0xFFAA00
            payload = {
                "embeds": [{
                    "title": "PROTOCOL PAUSED" if level == "critical" else "Suspicious Activity",
                    "description": message,
                    "color": color,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(self.discord_webhook, json=payload) as resp:
                    if resp.status not in (200, 204):
                        logger.warning(f"Discord alert failed: {resp.status}")
        except Exception as e:
            logger.warning(f"Discord send error: {e}")

    async def _send_telegram(self, message: str):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {"chat_id": self.telegram_chat_id, "text": message, "parse_mode": "Markdown"}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status != 200:
                        logger.warning(f"Telegram alert failed: {resp.status}")
        except Exception as e:
            logger.warning(f"Telegram send error: {e}")

    def _append_event(self, result: dict):
        """Write event to local JSON file AND Supabase."""

        # 1. Local file (always)
        try:
            existing = json.loads(EVENTS_LOG_PATH.read_text())
            existing.append(result)
            existing = existing[-100:]
            EVENTS_LOG_PATH.write_text(json.dumps(existing, indent=2))
        except Exception as e:
            logger.warning(f"Local log error: {e}")

        # 2. Supabase (if configured)
        try:
            sb = _get_supabase()
            if sb:
                sb.table("events").insert({
                    "tx_hash":            result.get("tx_hash", ""),
                    "action":             result.get("action", ""),
                    "attack_type":        result.get("attack_type", ""),
                    "confidence":         int(result.get("confidence", 0)),
                    "rationale":          result.get("rationale", ""),
                    "estimated_loss_usd": int(result.get("estimated_loss_usd", 0)),
                    "suspected_attacker": result.get("suspected_attacker", ""),
                    "pause_tx_hash":      result.get("pause_tx_hash"),
                    "success":            bool(result.get("success", False)),
                }).execute()
                logger.info("Event synced to Supabase")
        except Exception as e:
            logger.warning(f"Supabase write error: {e}")

    def write_report_to_supabase(self, report: dict):
        """Called by ReportGenerator after a pause fires."""
        try:
            sb = _get_supabase()
            if sb:
                sb.table("reports").insert({"data": report}).execute()
                logger.info("Incident report synced to Supabase")
        except Exception as e:
            logger.warning(f"Supabase report write error: {e}")
