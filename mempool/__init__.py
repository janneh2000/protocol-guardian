"""
Protocol Guardian v2 — Mempool Monitoring Module
================================================
Pre-transaction threat detection for DeFi protocols.
"""

from .monitor import MempoolMonitor, MempoolConfig, MonitorStats, create_monitor
from .decoder import TransactionDecoder, ThreatAnalyzer, ThreatReport, DecodedTransaction
from .patterns import AttackCategory, ExploitSignature, SELECTOR_INDEX, ALL_SIGNATURES
from .watchlist import Watchlist, PROTOCOL_REGISTRY, ProtocolEntry
from .simulator import EVMSimulator, SimulationResult, create_mock_simulation

__all__ = [
    "MempoolMonitor", "MempoolConfig", "MonitorStats", "create_monitor",
    "TransactionDecoder", "ThreatAnalyzer", "ThreatReport", "DecodedTransaction",
    "AttackCategory", "ExploitSignature", "SELECTOR_INDEX", "ALL_SIGNATURES",
    "Watchlist", "PROTOCOL_REGISTRY", "ProtocolEntry",
    "EVMSimulator", "SimulationResult", "create_mock_simulation",
]
