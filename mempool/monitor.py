"""
Protocol Guardian v2 — Mempool Monitor
=======================================
Real-time pending transaction monitor that connects to an Ethereum
node via WebSocket, subscribes to the mempool, and runs every
transaction through the threat analysis pipeline.

Architecture:
  Node (ws) → pending tx hashes → eth_getTransaction → Decoder → ThreatAnalyzer → Claude → Action

Supports:
  - WebSocket subscription to newPendingTransactions
  - HTTP polling fallback (for nodes without ws support)
  - Alchemy/Infura enhanced APIs (alchemy_pendingTransactions)
  - Configurable watchlist of protocol contracts
  - Rate-limited Claude API calls (only for high-risk txs)
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

logger = logging.getLogger("guardian.mempool")


@dataclass
class MempoolConfig:
    """Configuration for the mempool monitor."""
    # Node connection
    ws_url: str = "wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
    http_url: str = "https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"

    # Watchlist — contracts to monitor
    watched_contracts: set[str] = field(default_factory=lambda: {
        # Protocol Guardian demo contracts (Sepolia)
        "0x84568d45c653844bae9d459311dd3487fca2630e",  # MockLendingPool
        "0x2344b12ae58c9c097c8400edbb1f9fb4dfca12fe",  # ProtocolGuardian
    })

    # Major DeFi protocols to monitor (add mainnet addresses when ready)
    # Aave V3 Pool, Uniswap V3 Router, Compound cETH, MakerDAO Vat
    extended_watchlist: set[str] = field(default_factory=set)

    # Monitoring behavior
    use_enhanced_api: bool = True       # Use Alchemy alchemy_pendingTransactions
    poll_interval_ms: int = 500         # HTTP polling interval (fallback)
    max_pending_batch: int = 50         # Max txs to process per cycle
    analysis_timeout_s: float = 2.0     # Max time for threat analysis per tx

    # Risk thresholds
    alert_threshold: float = 0.4        # Minimum score to trigger alert
    pause_threshold: float = 0.8        # Score to trigger autonomous pause
    claude_threshold: float = 0.6       # Score to escalate to Claude

    # Rate limiting
    claude_rate_limit: int = 10         # Max Claude calls per minute
    alert_cooldown_s: float = 30.0      # Min seconds between alerts for same address

    @property
    def all_watched(self) -> set[str]:
        return self.watched_contracts | self.extended_watchlist


@dataclass
class MonitorStats:
    """Runtime statistics for the mempool monitor."""
    started_at: float = 0.0
    txs_seen: int = 0
    txs_analyzed: int = 0
    threats_detected: int = 0
    critical_threats: int = 0
    claude_calls: int = 0
    pauses_triggered: int = 0
    avg_latency_ms: float = 0.0
    last_threat_at: float = 0.0

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    def to_dict(self) -> dict:
        return {
            "uptime_s": round(self.uptime_seconds, 1),
            "txs_seen": self.txs_seen,
            "txs_analyzed": self.txs_analyzed,
            "threats_detected": self.threats_detected,
            "critical_threats": self.critical_threats,
            "claude_escalations": self.claude_calls,
            "pauses_triggered": self.pauses_triggered,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }


# Type alias for callbacks
ThreatCallback = Callable[["ThreatReport"], Awaitable[None]]


class MempoolMonitor:
    """
    Real-time mempool monitor with threat detection.

    Usage:
        monitor = MempoolMonitor(config)
        monitor.on_threat(my_alert_handler)
        monitor.on_critical(my_pause_handler)
        await monitor.start()
    """

    def __init__(self, config: MempoolConfig):
        self.config = config
        self.stats = MonitorStats()
        self._running = False
        self._threat_callbacks: list[ThreatCallback] = []
        self._critical_callbacks: list[ThreatCallback] = []
        self._alert_cooldowns: dict[str, float] = {}
        self._latencies: list[float] = []

        # Lazy imports — these are heavy
        self._decoder = None
        self._analyzer = None

    def _init_pipeline(self):
        """Initialize the analysis pipeline (lazy)."""
        from .decoder import TransactionDecoder, ThreatAnalyzer
        self._decoder = TransactionDecoder()
        self._analyzer = ThreatAnalyzer(
            watched_contracts=self.config.all_watched,
        )

    def on_threat(self, callback: ThreatCallback):
        """Register a callback for medium+ risk threats."""
        self._threat_callbacks.append(callback)

    def on_critical(self, callback: ThreatCallback):
        """Register a callback for critical threats (pause recommended)."""
        self._critical_callbacks.append(callback)

    async def start(self):
        """Start the mempool monitor (main entry point)."""
        self._init_pipeline()
        self.stats.started_at = time.time()
        self._running = True

        logger.info(
            "Protocol Guardian mempool monitor starting — "
            f"watching {len(self.config.all_watched)} contracts"
        )

        while self._running:
            try:
                if self.config.use_enhanced_api:
                    await self._run_enhanced_subscription()
                else:
                    await self._run_ws_subscription()
            except Exception as e:
                logger.error(f"Monitor connection error: {e}. Reconnecting in 5s...")
                await asyncio.sleep(5)

    async def stop(self):
        """Gracefully stop the monitor."""
        self._running = False
        logger.info(f"Monitor stopped. Stats: {self.stats.to_dict()}")

    # ─────────────────────────────────────────────────────
    # WebSocket subscription (standard newPendingTransactions)
    # ─────────────────────────────────────────────────────

    async def _run_ws_subscription(self):
        """Subscribe to pending transactions via standard WebSocket."""
        try:
            import websockets
        except ImportError:
            logger.error("websockets not installed. Run: pip3 install websockets")
            return

        async with websockets.connect(self.config.ws_url) as ws:
            # Subscribe to pending transactions
            sub_msg = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_subscribe",
                "params": ["newPendingTransactions"],
            })
            await ws.send(sub_msg)
            response = await ws.recv()
            sub_result = json.loads(response)
            sub_id = sub_result.get("result")
            logger.info(f"Subscribed to pending txs. Subscription ID: {sub_id}")

            while self._running:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                    data = json.loads(msg)
                    if "params" in data:
                        tx_hash = data["params"]["result"]
                        self.stats.txs_seen += 1
                        await self._process_tx_hash(tx_hash, ws)
                except asyncio.TimeoutError:
                    # Send keepalive
                    await ws.ping()

    async def _process_tx_hash(self, tx_hash: str, ws):
        """Fetch full transaction data and analyze it."""
        try:
            import websockets
        except ImportError:
            return

        # Fetch full transaction
        get_tx = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_getTransactionByHash",
            "params": [tx_hash],
        })
        await ws.send(get_tx)
        response = await asyncio.wait_for(ws.recv(), timeout=5)
        result = json.loads(response)
        raw_tx = result.get("result")

        if not raw_tx:
            return

        await self._analyze_raw_tx(raw_tx)

    # ─────────────────────────────────────────────────────
    # Enhanced API (Alchemy alchemy_pendingTransactions)
    # ─────────────────────────────────────────────────────

    async def _run_enhanced_subscription(self):
        """
        Use Alchemy's enhanced API to subscribe ONLY to pending txs
        targeting our watched contracts. Much more efficient.
        """
        try:
            import websockets
        except ImportError:
            logger.error("websockets not installed. Falling back to HTTP polling.")
            await self._run_http_polling()
            return

        async with websockets.connect(self.config.ws_url) as ws:
            # Alchemy enhanced subscription — filter by to_address
            watched = list(self.config.all_watched)
            sub_msg = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_subscribe",
                "params": [
                    "alchemy_pendingTransactions",
                    {
                        "toAddress": watched,
                        "hashesOnly": False,  # Get full tx data
                    },
                ],
            })
            await ws.send(sub_msg)
            response = await ws.recv()
            sub_result = json.loads(response)

            if "error" in sub_result:
                logger.warning(
                    f"Enhanced API not available: {sub_result['error']}. "
                    "Falling back to standard subscription."
                )
                await self._run_ws_subscription()
                return

            sub_id = sub_result.get("result")
            logger.info(
                f"Enhanced subscription active (ID: {sub_id}). "
                f"Filtering for {len(watched)} contracts."
            )

            while self._running:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=30)
                    data = json.loads(msg)
                    if "params" in data:
                        raw_tx = data["params"]["result"]
                        self.stats.txs_seen += 1
                        await self._analyze_raw_tx(raw_tx)
                except asyncio.TimeoutError:
                    await ws.ping()

    # ─────────────────────────────────────────────────────
    # HTTP Polling fallback
    # ─────────────────────────────────────────────────────

    async def _run_http_polling(self):
        """Fallback: poll pending transactions via HTTP JSON-RPC."""
        try:
            import aiohttp
        except ImportError:
            logger.error("aiohttp not installed. Run: pip3 install aiohttp")
            return

        seen_hashes: set[str] = set()

        async with aiohttp.ClientSession() as session:
            while self._running:
                try:
                    payload = json.dumps({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBlockByNumber",
                        "params": ["pending", True],
                    })
                    async with session.post(
                        self.config.http_url,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                    ) as resp:
                        result = await resp.json()
                        block = result.get("result", {})
                        txs = block.get("transactions", [])

                        for raw_tx in txs:
                            if isinstance(raw_tx, dict):
                                tx_hash = raw_tx.get("hash", "")
                                if tx_hash not in seen_hashes:
                                    seen_hashes.add(tx_hash)
                                    self.stats.txs_seen += 1
                                    await self._analyze_raw_tx(raw_tx)

                    # Trim seen set
                    if len(seen_hashes) > 10000:
                        seen_hashes = set(list(seen_hashes)[-5000:])

                except Exception as e:
                    logger.error(f"HTTP polling error: {e}")

                await asyncio.sleep(self.config.poll_interval_ms / 1000)

    # ─────────────────────────────────────────────────────
    # Core analysis pipeline
    # ─────────────────────────────────────────────────────

    async def _analyze_raw_tx(self, raw_tx: dict):
        """Run a raw transaction through the full threat pipeline."""
        try:
            # Decode
            tx = self._decoder.decode(raw_tx)

            # Quick filter: skip simple ETH transfers (no calldata)
            if not tx.has_calldata and tx.value_eth < self.config.all_watched.__len__():
                return

            # Analyze
            self.stats.txs_analyzed += 1
            report = self._analyzer.analyze(tx)

            # Track latency
            self._latencies.append(report.analysis_latency_ms)
            if len(self._latencies) > 100:
                self._latencies = self._latencies[-100:]
            self.stats.avg_latency_ms = sum(self._latencies) / len(self._latencies)

            # Act on results
            if report.is_threat:
                await self._handle_threat(report)

        except Exception as e:
            logger.error(f"Analysis error for tx {raw_tx.get('hash', '?')}: {e}")

    async def _handle_threat(self, report):
        """Handle a detected threat — dispatch to callbacks."""
        from .decoder import ThreatReport

        self.stats.threats_detected += 1
        self.stats.last_threat_at = time.time()

        # Check cooldown (avoid alert spam for same address)
        sender = report.tx.from_address
        now = time.time()
        last_alert = self._alert_cooldowns.get(sender, 0)
        if now - last_alert < self.config.alert_cooldown_s:
            return
        self._alert_cooldowns[sender] = now

        level = report.risk_level.upper()
        logger.warning(
            f"[{level}] Threat detected in mempool — "
            f"tx: {report.tx.tx_hash[:16]}... "
            f"from: {report.tx.from_address[:16]}... "
            f"score: {report.composite_risk_score:.2%} "
            f"categories: {report.attack_categories}"
        )

        if report.is_critical:
            self.stats.critical_threats += 1
            for cb in self._critical_callbacks:
                try:
                    await cb(report)
                except Exception as e:
                    logger.error(f"Critical callback error: {e}")

        for cb in self._threat_callbacks:
            try:
                await cb(report)
            except Exception as e:
                logger.error(f"Threat callback error: {e}")


# ─────────────────────────────────────────────────────────
# Convenience factory
# ─────────────────────────────────────────────────────────

def create_monitor(
    ws_url: str,
    http_url: str,
    watched_contracts: list[str],
    use_enhanced: bool = True,
) -> MempoolMonitor:
    """Create a configured mempool monitor."""
    config = MempoolConfig(
        ws_url=ws_url,
        http_url=http_url,
        watched_contracts={addr.lower() for addr in watched_contracts},
        use_enhanced_api=use_enhanced,
    )
    return MempoolMonitor(config)
