"""
swarm_client.py — Gensyn AXL client for the Protocol Guardian swarm.

Each Guardian instance runs its own AXL node (a userspace P2P node binary
from gensyn-ai/axl, built on Yggdrasil + gVisor). When one Guardian detects
a high-confidence threat in the mempool it broadcasts a threat-fingerprint
blob through its local AXL node's `/send` endpoint. Every peer Guardian
in the mesh polls its own local `/recv` endpoint and uses incoming
fingerprints to raise its confidence floor for matching transactions —
turning per-protocol monitoring into a coordinated swarm with no
centralised broker.

Wire format (binary, fixed-size, network byte order):
    magic       8 bytes   b'PGTHRT01'
    selector    4 bytes   function selector (e.g. 0xa9059cbb)
    target      20 bytes  target contract address
    confidence  1 byte    0..100
    ts          8 bytes   unix epoch seconds
    source_id   32 bytes  source AXL node pubkey (zeros if unknown)
    ----
    73 bytes total

The fingerprint is intentionally tiny so AXL `/send` carries it in a
single packet. Anything richer (full reasoning logs, Claude transcripts)
goes in the post-incident report stored elsewhere.

Configuration (env vars):
    AXL_BASE_URL    base URL of the local AXL HTTP API
                    (default: http://localhost:9090)
    AXL_NODE_ID     hex-encoded 32-byte source identifier (optional)
    AXL_TOPIC       logical topic to send/recv on (default: pg-threats)
"""

from __future__ import annotations

import asyncio
import logging
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional

import aiohttp

logger = logging.getLogger("guardian.axl")

_MAGIC = b"PGTHRT01"
_FORMAT = ">8s4s20sBQ32s"
_FRAME_SIZE = struct.calcsize(_FORMAT)
assert _FRAME_SIZE == 73, "wire format size drift"

_DEFAULT_BASE_URL = os.getenv("AXL_BASE_URL", "http://localhost:9090")
_NODE_ID_HEX = os.getenv("AXL_NODE_ID", "0" * 64)
_TOPIC = os.getenv("AXL_TOPIC", "pg-threats")


def _hex_to_id(hex_str: str) -> bytes:
    raw = bytes.fromhex(hex_str)
    if len(raw) > 32:
        return raw[:32]
    return raw.rjust(32, b"\x00")


def _addr_to_bytes(addr: str) -> bytes:
    s = addr.lower().removeprefix("0x")
    if len(s) != 40:
        raise ValueError(f"bad address: {addr!r}")
    return bytes.fromhex(s)


def _selector_to_bytes(sel: str) -> bytes:
    s = sel.lower().removeprefix("0x")
    if len(s) != 8:
        raise ValueError(f"bad function selector: {sel!r}")
    return bytes.fromhex(s)


@dataclass(frozen=True)
class ThreatFingerprint:
    """A single threat observation broadcast across the AXL mesh."""

    function_selector: str   # "0xa9059cbb"
    target_address: str      # "0x84568d45c653844BAe9d459311dD3487FcA2630E"
    confidence: int          # 0..100
    timestamp: int           # unix epoch seconds
    source_id: str = "0" * 64  # 32-byte hex; identifies the broadcasting node

    def encode(self) -> bytes:
        return struct.pack(
            _FORMAT,
            _MAGIC,
            _selector_to_bytes(self.function_selector),
            _addr_to_bytes(self.target_address),
            max(0, min(100, int(self.confidence))),
            int(self.timestamp),
            _hex_to_id(self.source_id),
        )

    @classmethod
    def decode(cls, blob: bytes) -> "ThreatFingerprint":
        if len(blob) != _FRAME_SIZE:
            raise ValueError(f"frame size {len(blob)} != {_FRAME_SIZE}")
        magic, sel, addr, conf, ts, src = struct.unpack(_FORMAT, blob)
        if magic != _MAGIC:
            raise ValueError(f"bad magic {magic!r}")
        return cls(
            function_selector="0x" + sel.hex(),
            target_address="0x" + addr.hex(),
            confidence=int(conf),
            timestamp=int(ts),
            source_id=src.hex(),
        )

    def matches_tx(self, tx_selector: str, tx_target: str) -> bool:
        """Used by the receiving Guardian to compare an incoming peer
        fingerprint against a transaction it's currently classifying."""
        try:
            return (
                _selector_to_bytes(self.function_selector)
                == _selector_to_bytes(tx_selector)
                and _addr_to_bytes(self.target_address) == _addr_to_bytes(tx_target)
            )
        except ValueError:
            return False


class AXLSwarmClient:
    """Async client wrapping a local AXL node's HTTP bridge.

    The AXL node binary (gensyn-ai/axl) listens on AXL_BASE_URL by default
    on port 9090 in our docker-compose setup. We use only the `/send` and
    `/recv` endpoints; topology + MCP routes are out of scope here.
    """

    def __init__(self, base_url: str = _DEFAULT_BASE_URL, topic: str = _TOPIC, timeout_s: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.topic = topic
        self.timeout_s = timeout_s
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout_s)
        )
        return self

    async def __aexit__(self, *exc):
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _ensure(self) -> aiohttp.ClientSession:
        if self._session is None:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout_s)
            )
        return self._session

    async def send(self, fp: ThreatFingerprint) -> bool:
        """POST a fingerprint to the local AXL node for fan-out across peers.

        Returns True on success, False on any failure (network, AXL down,
        etc.). The agent treats False as "swarm offline; act on local intel
        only" — never crashes the analysis path.
        """
        sess = await self._ensure()
        url = f"{self.base_url}/send"
        params = {"topic": self.topic}
        try:
            async with sess.post(url, params=params, data=fp.encode()) as resp:
                if resp.status >= 400:
                    body = await resp.text()
                    logger.warning("AXL send failed (%s): %s", resp.status, body[:120])
                    return False
                return True
        except Exception as e:
            logger.debug("AXL send error: %s", e)
            return False

    async def recv(self, max_messages: int = 64) -> list[ThreatFingerprint]:
        """Pull queued peer fingerprints from the local AXL node.

        Returns at most `max_messages` decoded fingerprints. Drops any frame
        we can't decode (wrong magic, wrong size). Never raises — empty list
        on transport failure.
        """
        sess = await self._ensure()
        url = f"{self.base_url}/recv"
        params = {"topic": self.topic, "limit": str(max_messages)}
        out: list[ThreatFingerprint] = []
        try:
            async with sess.get(url, params=params) as resp:
                if resp.status >= 400:
                    return out
                # AXL packs frames back-to-back. We slice on _FRAME_SIZE.
                payload = await resp.read()
                offset = 0
                while offset + _FRAME_SIZE <= len(payload):
                    frame = payload[offset : offset + _FRAME_SIZE]
                    offset += _FRAME_SIZE
                    try:
                        out.append(ThreatFingerprint.decode(frame))
                    except ValueError as e:
                        logger.debug("dropping bad AXL frame: %s", e)
                return out
        except Exception as e:
            logger.debug("AXL recv error: %s", e)
            return out


# ── Module-level convenience ──────────────────────────────────────────────
# These are what `agent/ai_agent.py` actually calls. They keep their own
# session so callers don't have to manage lifecycles for one-off broadcasts.
_singleton: Optional[AXLSwarmClient] = None


async def _get_client() -> AXLSwarmClient:
    global _singleton
    if _singleton is None:
        _singleton = AXLSwarmClient()
    return _singleton


async def broadcast_threat(
    function_selector: str,
    target_address: str,
    confidence: int,
) -> bool:
    fp = ThreatFingerprint(
        function_selector=function_selector,
        target_address=target_address,
        confidence=confidence,
        timestamp=int(time.time()),
        source_id=_NODE_ID_HEX,
    )
    client = await _get_client()
    ok = await client.send(fp)
    if ok:
        logger.info(
            "Broadcast threat fingerprint to swarm: selector=%s target=%s confidence=%d",
            function_selector, target_address, confidence,
        )
    return ok


async def recv_peer_threats() -> list[ThreatFingerprint]:
    client = await _get_client()
    fps = await client.recv()
    if fps:
        logger.info("Received %d peer threat fingerprint(s) from AXL swarm", len(fps))
    return fps
