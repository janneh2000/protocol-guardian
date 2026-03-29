"""
ingestion.py — HTTP polling ingestion layer (web3.py v7 compatible).
Polls for new blocks every 3 seconds and analyses transactions
touching the monitored protocol.
"""

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional
from web3 import Web3

logger = logging.getLogger("guardian.ingestion")


@dataclass
class TxContext:
    tx_hash: str
    from_addr: str
    to_addr: Optional[str]
    value_wei: int
    input_data: str
    gas: int
    gas_price: int
    block_number: Optional[int] = None
    block_timestamp: Optional[int] = None
    is_flash_loan: bool = False
    price_before: Optional[int] = None
    price_after: Optional[int] = None
    pool_balance_before: Optional[int] = None
    pool_balance_after: Optional[int] = None
    logs: list = field(default_factory=list)
    raw_tx: Optional[dict] = None


class BlockchainIngestion:
    FLASH_LOAN_SELECTORS = {
        "0xab9c4b5d", "0x5cffe9de", "0x42b0b77c",
        "0xd9d98ce4", "0xe8eda9df",
    }
    PRICE_UPDATE_SELECTORS = {
        "0x8a0dac4a", "0x00e4768b", "0x7e2d5753",
    }

    def __init__(self, ws_rpc_url: str, pool_address: str, on_suspicious_tx):
        http_rpc = os.getenv("ALCHEMY_HTTP_RPC") or os.getenv("ALCHEMY_SEPOLIA_RPC") or ""
        if not http_rpc and ws_rpc_url:
            http_rpc = ws_rpc_url.replace("wss://", "https://").replace("ws://", "http://")
        self.http_rpc = http_rpc
        self.pool_address = pool_address.lower()
        self.on_suspicious_tx = on_suspicious_tx
        self.w3 = Web3(Web3.HTTPProvider(http_rpc))
        self._running = False
        self._last_block = 0
        self._prev_balance = 0
        self._prev_price = 2000 * 10**18
        self._seen_hashes: set = set()
        self._pool_contract = None

    def _load_pool_contract(self):
        if self._pool_contract:
            return self._pool_contract
        try:
            abi_path = os.path.join(os.path.dirname(__file__), "../abi/MockLendingPool.json")
            if os.path.exists(abi_path):
                with open(abi_path) as f:
                    abi = json.load(f)
                self._pool_contract = self.w3.eth.contract(
                    address=Web3.to_checksum_address(self.pool_address), abi=abi
                )
        except Exception as e:
            logger.debug(f"Could not load pool contract: {e}")
        return self._pool_contract

    def _get_oracle_price(self) -> int:
        try:
            contract = self._load_pool_contract()
            if contract:
                return contract.functions.assetPrice().call()
        except Exception:
            pass
        return self._prev_price

    def _get_pool_balance(self) -> int:
        try:
            return self.w3.eth.get_balance(Web3.to_checksum_address(self.pool_address))
        except Exception:
            return self._prev_balance

    async def connect(self):
        if not self.w3.is_connected():
            raise ConnectionError("Failed to connect to Ethereum node via HTTP RPC")
        block = self.w3.eth.block_number
        self._last_block = block
        self._prev_balance = self._get_pool_balance()
        self._prev_price = self._get_oracle_price()
        logger.info(f"Connected via HTTP RPC | Current block: {block}")
        logger.info(f"Pool balance: {self._prev_balance / 1e18:.6f} ETH")
        logger.info(f"Oracle price: ${self._prev_price / 1e18:,.2f}")
        return self.w3

    async def start(self):
        self._running = True
        await self.connect()
        logger.info(f"Monitoring pool: {self.pool_address}")
        logger.info("Polling for new blocks every 3 seconds...")
        await self._poll_loop()

    async def stop(self):
        self._running = False

    async def _poll_loop(self):
        while self._running:
            try:
                latest = self.w3.eth.block_number
                if latest > self._last_block:
                    for block_num in range(self._last_block + 1, latest + 1):
                        await self._process_block(block_num)
                    self._last_block = latest
            except Exception as e:
                logger.debug(f"Poll error: {e}")
            await asyncio.sleep(3)

    async def _process_block(self, block_number: int):
        try:
            block = self.w3.eth.get_block(block_number, full_transactions=True)
            txs = block.get("transactions", [])
            current_balance = self._get_pool_balance()
            current_price = self._get_oracle_price()

            if self._prev_balance > 0:
                drain_pct = (self._prev_balance - current_balance) / self._prev_balance * 100
                if drain_pct > 20:
                    logger.warning(f"Block {block_number}: Pool drained {drain_pct:.1f}%!")
            if self._prev_price > 0:
                price_chg = abs(current_price - self._prev_price) / self._prev_price * 100
                if price_chg > 5:
                    logger.warning(f"Block {block_number}: Price moved {price_chg:.1f}%!")

            for tx in txs:
                await self._analyse_tx(tx, block_number, current_balance, current_price)

            self._prev_balance = current_balance
            self._prev_price = current_price
        except Exception as e:
            logger.debug(f"Error processing block {block_number}: {e}")

    async def _analyse_tx(self, tx, block_number: int, pool_balance: int, price: int):
        try:
            tx_hash = tx.get("hash", b"")
            if isinstance(tx_hash, bytes):
                tx_hash = "0x" + tx_hash.hex()
            else:
                tx_hash = str(tx_hash)

            if tx_hash in self._seen_hashes:
                return
            self._seen_hashes.add(tx_hash)
            if len(self._seen_hashes) > 2000:
                self._seen_hashes = set(list(self._seen_hashes)[-1000:])

            to_addr = (tx.get("to") or "").lower()
            input_data = tx.get("input", "0x")
            if isinstance(input_data, bytes):
                input_data = "0x" + input_data.hex()

            selector = input_data[:10].lower() if len(input_data) >= 10 else ""
            touches_pool = to_addr == self.pool_address
            is_flash_loan = selector in self.FLASH_LOAN_SELECTORS
            is_price_update = selector in self.PRICE_UPDATE_SELECTORS

            if not (touches_pool or is_flash_loan or is_price_update):
                return

            logger.info(f"Suspicious tx block {block_number}: {tx_hash[:18]}... pool={touches_pool} flash={is_flash_loan} price_update={is_price_update}")

            ctx = TxContext(
                tx_hash=tx_hash,
                from_addr=(tx.get("from") or "").lower(),
                to_addr=to_addr,
                value_wei=tx.get("value", 0),
                input_data=input_data,
                gas=tx.get("gas", 0),
                gas_price=tx.get("gasPrice", 0),
                block_number=block_number,
                is_flash_loan=is_flash_loan,
                pool_balance_before=self._prev_balance,
                pool_balance_after=pool_balance,
                price_before=self._prev_price,
                price_after=price,
                raw_tx={k: str(v) for k, v in tx.items() if k != "input"},
            )
            await self.on_suspicious_tx(ctx, source=f"block_{block_number}")
        except Exception as e:
            logger.debug(f"Error analysing tx: {e}")
