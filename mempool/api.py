"""
Protocol Guardian v2 — FastAPI Mempool Integration
===================================================
Connects the mempool monitor to the existing Protocol Guardian
agent pipeline. Provides:
  - /mempool/status     — Monitor health + stats
  - /mempool/threats    — Recent threat feed (SSE)
  - /mempool/watchlist  — Manage watched contracts
  - /mempool/config     — Runtime configuration
  
Integrates with Claude for high-risk threat assessment.
"""

import asyncio
import json
import logging
import os
import time
from collections import deque
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────
# Pydantic models for API
# ─────────────────────────────────────────────────────────

class WatchlistUpdate(BaseModel):
    address: str
    label: Optional[str] = None
    action: str = "add"  # "add" or "remove"


class ThreatSummary(BaseModel):
    tx_hash: str
    from_address: str
    to_address: Optional[str]
    value_eth: float
    risk_score: float
    risk_level: str
    categories: list[str]
    recommended_action: str
    indicator_count: int
    analysis_latency_ms: float
    timestamp: float
    claude_assessment: Optional[str] = None


class MempoolStatusResponse(BaseModel):
    status: str
    uptime_s: float
    txs_seen: int
    txs_analyzed: int
    threats_detected: int
    critical_threats: int
    claude_escalations: int
    avg_latency_ms: float
    watched_contracts: int
    recent_threats: list[ThreatSummary]


# ─────────────────────────────────────────────────────────
# Claude risk assessment integration
# ─────────────────────────────────────────────────────────

class ClaudeRiskAssessor:
    """Sends high-risk threat reports to Claude for analysis."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self._call_count = 0
        self._last_reset = time.time()
        self._rate_limit = 10  # calls per minute

    async def assess(self, claude_context: str) -> Optional[str]:
        """Send threat intelligence to Claude for risk assessment."""
        if not self.api_key:
            return "[Claude API key not configured — running in simulation mode]"

        # Rate limiting
        now = time.time()
        if now - self._last_reset > 60:
            self._call_count = 0
            self._last_reset = now
        if self._call_count >= self._rate_limit:
            return "[Rate limited — too many Claude calls this minute]"

        try:
            import httpx

            self._call_count += 1

            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 1024,
                        "system": (
                            "You are Protocol Guardian's AI risk assessment engine. "
                            "You analyze pending Ethereum transactions detected in the mempool "
                            "BEFORE they are confirmed on-chain. Your job is to classify threats "
                            "and recommend autonomous defensive actions (pause, alert, or monitor). "
                            "Be decisive. False negatives cost millions; false positives cost gas. "
                            "Respond in JSON: {risk_assessment, confidence, action, reasoning}"
                        ),
                        "messages": [{"role": "user", "content": claude_context}],
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data["content"][0]["text"]
                else:
                    return f"[Claude API error: {response.status_code}]"

        except ImportError:
            return "[httpx not installed — Claude integration requires: pip3 install httpx]"
        except Exception as e:
            return f"[Claude assessment failed: {e}]"


# ─────────────────────────────────────────────────────────
# Mempool API Router
# ─────────────────────────────────────────────────────────

class MempoolAPI:
    """
    FastAPI router for the mempool monitoring module.
    Attach to your existing FastAPI app with:
        mempool_api = MempoolAPI(app)
        await mempool_api.start_monitor(ws_url, http_url, contracts)
    """

    def __init__(self, app: FastAPI):
        self.app = app
        self.monitor = None
        self.claude = ClaudeRiskAssessor()
        self.recent_threats: deque[ThreatSummary] = deque(maxlen=100)
        self._threat_subscribers: list[asyncio.Queue] = []

        self._register_routes()

    def _register_routes(self):
        """Register FastAPI endpoints."""

        @self.app.get("/mempool/status", response_model=MempoolStatusResponse)
        async def get_status():
            if not self.monitor:
                raise HTTPException(503, "Mempool monitor not started")
            stats = self.monitor.stats
            return MempoolStatusResponse(
                status="running" if self.monitor._running else "stopped",
                uptime_s=round(stats.uptime_seconds, 1),
                txs_seen=stats.txs_seen,
                txs_analyzed=stats.txs_analyzed,
                threats_detected=stats.threats_detected,
                critical_threats=stats.critical_threats,
                claude_escalations=stats.claude_calls,
                avg_latency_ms=round(stats.avg_latency_ms, 2),
                watched_contracts=len(self.monitor.config.all_watched),
                recent_threats=list(self.recent_threats)[-10:],
            )

        @self.app.get("/mempool/threats/stream")
        async def stream_threats():
            """Server-Sent Events stream of real-time threat detections."""
            queue: asyncio.Queue = asyncio.Queue()
            self._threat_subscribers.append(queue)

            async def event_generator():
                try:
                    while True:
                        threat = await queue.get()
                        yield f"data: {json.dumps(threat)}\n\n"
                except asyncio.CancelledError:
                    pass
                finally:
                    self._threat_subscribers.remove(queue)

            return StreamingResponse(
                event_generator(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )

        @self.app.get("/mempool/threats")
        async def get_recent_threats():
            return {"threats": list(self.recent_threats)[-20:]}

        @self.app.post("/mempool/watchlist")
        async def update_watchlist(update: WatchlistUpdate):
            if not self.monitor:
                raise HTTPException(503, "Monitor not started")
            addr = update.address.lower()
            if update.action == "add":
                self.monitor.config.watched_contracts.add(addr)
                return {"status": "added", "address": addr}
            elif update.action == "remove":
                self.monitor.config.watched_contracts.discard(addr)
                return {"status": "removed", "address": addr}
            raise HTTPException(400, "Action must be 'add' or 'remove'")

        @self.app.get("/mempool/watchlist")
        async def get_watchlist():
            if not self.monitor:
                return {"contracts": []}
            return {"contracts": sorted(self.monitor.config.all_watched)}

        @self.app.get("/mempool/stats")
        async def get_stats():
            if not self.monitor:
                raise HTTPException(503, "Monitor not started")
            return self.monitor.stats.to_dict()

    async def start_monitor(
        self,
        ws_url: str,
        http_url: str,
        watched_contracts: list[str],
        use_enhanced: bool = True,
    ):
        """Start the mempool monitor with callbacks wired to the API."""
        from mempool.monitor import create_monitor

        self.monitor = create_monitor(ws_url, http_url, watched_contracts, use_enhanced)

        # Wire callbacks
        self.monitor.on_threat(self._on_threat)
        self.monitor.on_critical(self._on_critical)

        # Start in background
        asyncio.create_task(self.monitor.start())

    async def _on_threat(self, report):
        """Handle detected threats — store, broadcast, and optionally escalate to Claude."""
        summary = ThreatSummary(
            tx_hash=report.tx.tx_hash,
            from_address=report.tx.from_address,
            to_address=report.tx.to_address,
            value_eth=report.tx.value_eth,
            risk_score=report.composite_risk_score,
            risk_level=report.risk_level,
            categories=report.attack_categories,
            recommended_action=report.recommended_action,
            indicator_count=len(report.indicators),
            analysis_latency_ms=report.analysis_latency_ms,
            timestamp=time.time(),
        )

        # Escalate to Claude for high-risk threats
        if report.composite_risk_score >= self.monitor.config.claude_threshold:
            assessment = await self.claude.assess(report.claude_context)
            summary.claude_assessment = assessment
            if self.monitor:
                self.monitor.stats.claude_calls += 1

        self.recent_threats.append(summary)

        # Broadcast to SSE subscribers
        threat_dict = summary.model_dump()
        for queue in self._threat_subscribers:
            try:
                queue.put_nowait(threat_dict)
            except asyncio.QueueFull:
                pass

    async def _on_critical(self, report):
        """Handle critical threats — trigger autonomous pause."""
        logging.getLogger("guardian.mempool").critical(
            f"CRITICAL THREAT — AUTONOMOUS PAUSE RECOMMENDED\n"
            f"  TX: {report.tx.tx_hash}\n"
            f"  Score: {report.composite_risk_score:.2%}\n"
            f"  Categories: {report.attack_categories}\n"
            f"  Action: {report.recommended_action}\n"
        )
        if self.monitor:
            self.monitor.stats.pauses_triggered += 1

        # In production, this would call the ProtocolGuardian contract's pause()
        # await self._execute_pause(report.tx.to_address)


# ─────────────────────────────────────────────────────────
# Quick-start helper
# ─────────────────────────────────────────────────────────

def setup_mempool_routes(app: FastAPI) -> MempoolAPI:
    """One-liner to add mempool monitoring to an existing FastAPI app."""
    return MempoolAPI(app)
