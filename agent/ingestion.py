"""
ingestion.py — Real-time blockchain data ingestion layer.

Subscribes to:
  - newPendingTransactions (mempool)
  - newHeads (new blocks)
  - protocol contract logs (event-level monitoring)

Feeds suspicious transactions into the heuristics engine.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from web3 import AsyncWeb3, WebSocketProvider
from web3.types import TxData

logger = logging.getLogger("guardian.ingestion")


@dataclass
class TxContext:
    """Enriched transaction context passed to the heuristics engine."""
    tx_hash: str
    from_addr: str
    to_addr: Optional[str]
    value_wei: int
    input_data: str
    gas: int
    gas_price: int
    block_number: Optional[int] = None
    block_timestamp: Optional[int] = None
    # Enrichment fields
    is_flash_loan: bool = False
    price_before: Optional[int] = None
    price_after: Optional[int] = None
    pool_balance_before: Optional[int] = None
    pool_balance_after: Optional[int] = None
    logs: list = field(default_factory=list)
    trace: Optional[dict] = None
    raw_tx: Optional[dict] = None


class BlockchainIngestion:
    """
    Connects to Alchemy via WebSocket and streams pending transactions
    and block data. Enriches transactions involving the monitored protocol
    and hands them to the heuristics callback.
    """

    FLASH_LOAN_SELECTORS = {
        "0xab9c4b5d",  # flashLoan(address,uint256,bytes)
        "0x5cffe9de",  # flashLoan (Aave V2)
        "0x42b0b77c",  # flashLoanSimple (Aave V3)
        "0xd9d98ce4",  # flash (Uniswap V3)
    }

    def __init__(self, ws_rpc_url: str, pool_address: str, on_suspicious_tx):
        self.ws_rpc_url = ws_rpc_url
        self.pool_address = pool_address.lower()
        self.on_suspicious_tx = on_suspicious_tx
        self.w3: Optional[AsyncWeb3] = None
        self._running = False

    async def connect(self):
        logger.info("Connecting to Alchemy WebSocket...")
        self.w3 = AsyncWeb3(WebSocketProvider(self.ws_rpc_url))
        connected = await self.w3.is_connected()
        if not connected:
            raise ConnectionError("Failed to connect to Alchemy WebSocket")
        logger.info("Connected to Ethereum node via WebSocket")
        return self.w3

    async def start(self):
        self._running = True
        await self.connect()
        logger.info(f"Monitoring pool: {self.pool_address}")
        logger.info("Starting mempool and block subscriptions...")

        await asyncio.gather(
            self._subscribe_mempool(),
            self._subscribe_blocks(),
        )

    async def stop(self):
        self._running = False
        logger.info("Ingestion stopped")

    async def _subscribe_mempool(self):
        """Watch pending transactions for interactions with the protocol."""
        logger.info("Subscribed to pending transactions (mempool)")
        subscription_id = await self.w3.eth.subscribe("newPendingTransactions")

        async for tx_hash in self.w3.socket.process_subscriptions():
            if not self._running:
                break
            if isinstance(tx_hash, bytes):
                tx_hash = tx_hash.hex()
            if isinstance(tx_hash, dict) and "result" in tx_hash:
                tx_hash = tx_hash["result"]

            asyncio.create_task(self._process_pending_tx(tx_hash))

    async def _subscribe_blocks(self):
        """Watch new blocks for post-confirmation analysis."""
        logger.info("Subscribed to new blocks")
        subscription_id = await self.w3.eth.subscribe("newHeads")

        async for block_header in self.w3.socket.process_subscriptions():
            if not self._running:
                break
            if isinstance(block_header, dict) and "number" in block_header:
                block_num = int(block_header["number"], 16)
                asyncio.create_task(self._process_block(block_num))

    async def _process_pending_tx(self, tx_hash: str):
        """
        Fetch pending tx details. If it touches the monitored protocol
        or matches a flash loan selector, enrich and forward it.
        """
        try:
            tx = await self.w3.eth.get_transaction(tx_hash)
            if tx is None:
                return

            to_addr = (tx.get("to") or "").lower()
            input_data = tx.get("input", "0x")
            if isinstance(input_data, bytes):
                input_data = "0x" + input_data.hex()

            # Check 1: Does this tx interact with the pool directly?
            touches_pool = to_addr == self.pool_address

            # Check 2: Is this a flash loan call (any protocol)?
            selector = input_data[:10].lower() if len(input_data) >= 10 else ""
            is_flash_loan = selector in self.FLASH_LOAN_SELECTORS

            if not (touches_pool or is_flash_loan):
                return

            logger.debug(f"Interesting pending tx: {tx_hash} | touches_pool={touches_pool} | flash_loan={is_flash_loan}")

            # Fetch current pool state as baseline
            pool_balance = await self.w3.eth.get_balance(
                self.w3.to_checksum_address(self.pool_address)
            )
            price = await self._get_oracle_price()

            ctx = TxContext(
                tx_hash=tx_hash,
                from_addr=(tx.get("from") or "").lower(),
                to_addr=to_addr,
                value_wei=tx.get("value", 0),
                input_data=input_data,
                gas=tx.get("gas", 0),
                gas_price=tx.get("gasPrice", 0),
                is_flash_loan=is_flash_loan,
                price_before=price,
                pool_balance_before=pool_balance,
                raw_tx=dict(tx),
            )

            await self.on_suspicious_tx(ctx, source="mempool")

        except Exception as e:
            logger.debug(f"Error processing pending tx {tx_hash}: {e}")

    async def _process_block(self, block_number: int):
        """
        On each new block, check if the pool's balance changed significantly
        or if the oracle price was manipulated.
        """
        try:
            block = await self.w3.eth.get_block(block_number, full_transactions=True)
            pool_balance = await self.w3.eth.get_balance(
                self.w3.to_checksum_address(self.pool_address)
            )
            price = await self._get_oracle_price()

            # Store snapshots for comparison (simple ring buffer approach)
            if not hasattr(self, "_prev_balance"):
                self._prev_balance = pool_balance
                self._prev_price = price
                return

            balance_change_pct = abs(pool_balance - self._prev_balance) / max(self._prev_balance, 1) * 100
            price_change_pct = abs(price - self._prev_price) / max(self._prev_price, 1) * 100

            if balance_change_pct > 20:
                logger.warning(f"Block {block_number}: Pool balance dropped {balance_change_pct:.1f}%!")
                await self._raise_block_level_alert(block, "large_balance_change", balance_change_pct, pool_balance, price)

            if price_change_pct > 10:
                logger.warning(f"Block {block_number}: Oracle price moved {price_change_pct:.1f}%!")
                await self._raise_block_level_alert(block, "price_manipulation", price_change_pct, pool_balance, price)

            self._prev_balance = pool_balance
            self._prev_price = price

        except Exception as e:
            logger.debug(f"Error processing block {block_number}: {e}")

    async def _raise_block_level_alert(self, block, alert_type, change_pct, pool_balance, price):
        """Synthesise a TxContext from a block-level anomaly."""
        # Find the tx in this block that most likely caused the anomaly
        txs = block.get("transactions", [])
        suspect_tx = None
        for tx in txs:
            to_addr = (tx.get("to") or "").lower()
            if to_addr == self.pool_address:
                suspect_tx = tx
                break
        if not suspect_tx and txs:
            suspect_tx = txs[-1]

        if not suspect_tx:
            return

        input_data = suspect_tx.get("input", "0x")
        if isinstance(input_data, bytes):
            input_data = "0x" + input_data.hex()

        ctx = TxContext(
            tx_hash=suspect_tx.get("hash", b"").hex() if isinstance(suspect_tx.get("hash"), bytes) else str(suspect_tx.get("hash", "")),
            from_addr=(suspect_tx.get("from") or "").lower(),
            to_addr=(suspect_tx.get("to") or "").lower(),
            value_wei=suspect_tx.get("value", 0),
            input_data=input_data,
            gas=suspect_tx.get("gas", 0),
            gas_price=suspect_tx.get("gasPrice", 0),
            block_number=block.get("number"),
            pool_balance_after=pool_balance,
            price_after=price,
            raw_tx={"alert_type": alert_type, "change_pct": change_pct},
        )
        await self.on_suspicious_tx(ctx, source=f"block_{alert_type}")

    async def _get_oracle_price(self) -> int:
        """Fetch the current oracle price from the lending pool."""
        try:
            from web3 import Web3
            # Load ABI lazily
            import json, os
            abi_path = os.path.join(os.path.dirname(__file__), "../abi/MockLendingPool.json")
            if not os.path.exists(abi_path):
                return 2000 * 10**18
            with open(abi_path) as f:
                abi = json.load(f)
            contract = self.w3.eth.contract(
                address=self.w3.to_checksum_address(self.pool_address),
                abi=abi
            )
            return await contract.functions.assetPrice().call()
        except Exception:
            return 2000 * 10**18  # fallback
