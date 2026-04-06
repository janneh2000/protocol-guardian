"""
Protocol Guardian v2 — Multi-Protocol Watchlist
=================================================
Configurable registry of DeFi protocols to monitor.
Demonstrates Protocol Guardian can protect the entire
ecosystem, not just a single contract.

Each protocol entry includes:
  - Contract addresses (multiple per protocol)
  - Chain information
  - Risk profile and TVL
  - Critical function signatures to watch
  - Alert configuration

Usage:
    from mempool.watchlist import Watchlist, PROTOCOL_REGISTRY
    wl = Watchlist()
    wl.add_from_registry("aave_v3")
    wl.add_from_registry("uniswap_v3")
    all_addresses = wl.get_all_addresses()
"""

import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger("guardian.watchlist")


class Chain(str, Enum):
    ETHEREUM = "ethereum"
    SEPOLIA = "sepolia"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BSC = "bsc"
    BASE = "base"
    AVALANCHE = "avalanche"


class RiskTier(str, Enum):
    CRITICAL = "critical"    # Bridges, lending pools with >$1B TVL
    HIGH = "high"            # Major DEXs, yield protocols
    MEDIUM = "medium"        # Smaller protocols, new deployments
    DEMO = "demo"            # Testnet / hackathon demo contracts


@dataclass
class WatchedContract:
    """A single contract address being monitored."""
    address: str
    label: str
    role: str  # "pool", "router", "vault", "proxy", "governance", "oracle"
    critical_selectors: list[str] = field(default_factory=list)


@dataclass
class ProtocolEntry:
    """A DeFi protocol in the watchlist registry."""
    id: str
    name: str
    chain: Chain
    risk_tier: RiskTier
    category: str  # "lending", "dex", "bridge", "yield", "governance", "stablecoin"
    tvl_usd: Optional[float] = None
    tvl_display: Optional[str] = None
    description: str = ""
    contracts: list[WatchedContract] = field(default_factory=list)
    website: Optional[str] = None
    active: bool = True

    @property
    def all_addresses(self) -> list[str]:
        return [c.address.lower() for c in self.contracts]

    @property
    def all_selectors(self) -> list[str]:
        sels = set()
        for c in self.contracts:
            sels.update(c.critical_selectors)
        return list(sels)


# ─────────────────────────────────────────────────────────
# PROTOCOL REGISTRY
# ─────────────────────────────────────────────────────────

PROTOCOL_REGISTRY: dict[str, ProtocolEntry] = {

    # ── Demo / Testnet (Sepolia) ─────────────────────────

    "guardian_demo": ProtocolEntry(
        id="guardian_demo",
        name="Protocol Guardian Demo",
        chain=Chain.SEPOLIA,
        risk_tier=RiskTier.DEMO,
        category="lending",
        description="Protocol Guardian hackathon demo contracts on Sepolia testnet",
        contracts=[
            WatchedContract(
                address="0x84568d45c653844BAe9d459311dD3487FcA2630E",
                label="MockLendingPool",
                role="pool",
                critical_selectors=["0x3ccfd60b", "0x853828b6", "0x2e1a7d4d", "0xd0e30db0"],
            ),
            WatchedContract(
                address="0x2344B12ae58c9c097C8400edbB1f9fB4DfCA12fE",
                label="ProtocolGuardian",
                role="proxy",
                critical_selectors=["0x4f1ef286", "0x3659cfe6", "0xf2fde38b", "0x8456cb59"],
            ),
        ],
        active=True,
    ),

    # ── Lending ──────────────────────────────────────────

    "aave_v3": ProtocolEntry(
        id="aave_v3",
        name="Aave V3",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="lending",
        tvl_usd=12_500_000_000,
        tvl_display="$12.5B",
        description="Largest decentralized lending protocol. Flash loans, variable/stable rates.",
        website="https://aave.com",
        contracts=[
            WatchedContract(
                address="0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
                label="Aave V3 Pool",
                role="pool",
                critical_selectors=[
                    "0xab9c4b5d",  # flashLoan
                    "0x5cffe9de",  # flashLoanSimple
                    "0x69328dec",  # withdraw
                    "0x617ba037",  # supply
                    "0xa415bcad",  # borrow
                    "0x573ade81",  # repay
                    "0xe8eda9df",  # liquidationCall
                ],
            ),
            WatchedContract(
                address="0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e",
                label="Aave V3 PoolAddressesProvider",
                role="proxy",
                critical_selectors=["0xf2fde38b", "0x4f1ef286"],
            ),
        ],
        active=False,  # Activate when mainnet keys are configured
    ),

    "aave_v2": ProtocolEntry(
        id="aave_v2",
        name="Aave V2",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="lending",
        tvl_usd=3_200_000_000,
        tvl_display="$3.2B",
        description="Previous generation Aave. Still holds significant TVL.",
        contracts=[
            WatchedContract(
                address="0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
                label="Aave V2 LendingPool",
                role="pool",
                critical_selectors=["0x5cffe9de", "0x69328dec", "0xe8eda9df"],
            ),
        ],
        active=False,
    ),

    "compound_v3": ProtocolEntry(
        id="compound_v3",
        name="Compound V3 (Comet)",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="lending",
        tvl_usd=2_800_000_000,
        tvl_display="$2.8B",
        description="Single-asset lending markets. Simplified architecture.",
        contracts=[
            WatchedContract(
                address="0xc3d688B66703497DAA19211EEdff47f25384cdc3",
                label="cUSDCv3 (Comet)",
                role="pool",
                critical_selectors=["0x2e1a7d4d", "0xd0e30db0", "0xdb006a75"],
            ),
            WatchedContract(
                address="0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B",
                label="Comptroller",
                role="governance",
                critical_selectors=["0xda95691a", "0xfe0d94c1"],
            ),
        ],
        active=False,
    ),

    # ── DEX ──────────────────────────────────────────────

    "uniswap_v3": ProtocolEntry(
        id="uniswap_v3",
        name="Uniswap V3",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.HIGH,
        category="dex",
        tvl_usd=4_500_000_000,
        tvl_display="$4.5B",
        description="Concentrated liquidity DEX. Most traded on Ethereum.",
        contracts=[
            WatchedContract(
                address="0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
                label="SwapRouter02",
                role="router",
                critical_selectors=["0x128acb08", "0x022c0d9f"],
            ),
            WatchedContract(
                address="0x1F98431c8aD98523631AE4a59f267346ea31F984",
                label="UniswapV3Factory",
                role="governance",
                critical_selectors=["0xf2fde38b"],
            ),
        ],
        active=False,
    ),

    # ── Vaults / Yield ───────────────────────────────────

    "makerdao": ProtocolEntry(
        id="makerdao",
        name="MakerDAO (Sky)",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="stablecoin",
        tvl_usd=8_200_000_000,
        tvl_display="$8.2B",
        description="DAI stablecoin issuer. Core Ethereum DeFi infrastructure.",
        contracts=[
            WatchedContract(
                address="0x35D1b3F3D7966A1DFe207aa4514C12a259A0492B",
                label="Vat (Core Vault Engine)",
                role="vault",
                critical_selectors=["0x2e1a7d4d"],
            ),
            WatchedContract(
                address="0x9759A6Ac90977b93B58547b4A71c78317f391A28",
                label="DSPause (Governance Timelock)",
                role="governance",
                critical_selectors=["0xda95691a", "0xfe0d94c1"],
            ),
        ],
        active=False,
    ),

    "lido": ProtocolEntry(
        id="lido",
        name="Lido",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="staking",
        tvl_usd=15_000_000_000,
        tvl_display="$15B",
        description="Largest liquid staking protocol. stETH is a systemic DeFi asset.",
        contracts=[
            WatchedContract(
                address="0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84",
                label="stETH (Lido)",
                role="pool",
                critical_selectors=["0xa1903eab", "0x2e1a7d4d"],
            ),
        ],
        active=False,
    ),

    # ── Bridges ──────────────────────────────────────────

    "wormhole": ProtocolEntry(
        id="wormhole",
        name="Wormhole",
        chain=Chain.ETHEREUM,
        risk_tier=RiskTier.CRITICAL,
        category="bridge",
        tvl_usd=2_000_000_000,
        tvl_display="$2B",
        description="Cross-chain messaging. Previously exploited for $326M.",
        contracts=[
            WatchedContract(
                address="0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B",
                label="Wormhole Core Bridge",
                role="pool",
                critical_selectors=["0x4f1ef286", "0x3659cfe6"],
            ),
        ],
        active=False,
    ),
}


# ─────────────────────────────────────────────────────────
# Watchlist Manager
# ─────────────────────────────────────────────────────────

class Watchlist:
    """
    Manages the set of protocols and contracts being monitored.
    Provides unified address lists for the mempool monitor.
    """

    def __init__(self):
        self._active: dict[str, ProtocolEntry] = {}
        # Auto-add demo contracts
        self.add_from_registry("guardian_demo")

    def add_from_registry(self, protocol_id: str) -> bool:
        """Activate a protocol from the registry."""
        entry = PROTOCOL_REGISTRY.get(protocol_id)
        if not entry:
            logger.warning(f"Protocol '{protocol_id}' not found in registry")
            return False
        self._active[protocol_id] = entry
        entry.active = True
        logger.info(f"Watchlist: Added {entry.name} ({len(entry.contracts)} contracts, {entry.chain.value})")
        return True

    def remove(self, protocol_id: str) -> bool:
        """Remove a protocol from active monitoring."""
        if protocol_id in self._active:
            self._active[protocol_id].active = False
            del self._active[protocol_id]
            return True
        return False

    def add_custom(self, address: str, label: str, chain: str = "ethereum") -> bool:
        """Add a custom contract address not in the registry."""
        custom_id = f"custom_{address[:10]}"
        entry = ProtocolEntry(
            id=custom_id,
            name=label,
            chain=Chain(chain),
            risk_tier=RiskTier.MEDIUM,
            category="custom",
            contracts=[WatchedContract(address=address, label=label, role="unknown")],
            active=True,
        )
        self._active[custom_id] = entry
        logger.info(f"Watchlist: Added custom contract {label} ({address[:16]}...)")
        return True

    def get_all_addresses(self) -> set[str]:
        """Get all contract addresses across all active protocols."""
        addrs = set()
        for entry in self._active.values():
            for c in entry.contracts:
                addrs.add(c.address.lower())
        return addrs

    def get_all_selectors(self) -> set[str]:
        """Get all critical function selectors across all protocols."""
        sels = set()
        for entry in self._active.values():
            sels.update(entry.all_selectors)
        return sels

    def get_protocol_for_address(self, address: str) -> Optional[ProtocolEntry]:
        """Look up which protocol a contract address belongs to."""
        addr = address.lower()
        for entry in self._active.values():
            if addr in entry.all_addresses:
                return entry
        return None

    def get_contract_label(self, address: str) -> str:
        """Get a human-readable label for a contract address."""
        addr = address.lower()
        for entry in self._active.values():
            for c in entry.contracts:
                if c.address.lower() == addr:
                    return f"{entry.name} — {c.label}"
        return address[:16] + "..."

    def get_status(self) -> dict:
        """Get watchlist status summary."""
        total_tvl = sum(e.tvl_usd or 0 for e in self._active.values())
        return {
            "active_protocols": len(self._active),
            "total_contracts": sum(len(e.contracts) for e in self._active.values()),
            "total_tvl_display": f"${total_tvl/1e9:.1f}B" if total_tvl > 0 else "N/A",
            "chains": list(set(e.chain.value for e in self._active.values())),
            "protocols": [
                {
                    "id": e.id,
                    "name": e.name,
                    "chain": e.chain.value,
                    "risk_tier": e.risk_tier.value,
                    "category": e.category,
                    "contracts": len(e.contracts),
                    "tvl": e.tvl_display or "N/A",
                }
                for e in self._active.values()
            ],
        }

    def get_registry_status(self) -> list[dict]:
        """Get all available protocols (active and inactive)."""
        return [
            {
                "id": e.id,
                "name": e.name,
                "chain": e.chain.value,
                "category": e.category,
                "tvl": e.tvl_display or "N/A",
                "contracts": len(e.contracts),
                "active": e.id in self._active,
            }
            for e in PROTOCOL_REGISTRY.values()
        ]


# ─────────────────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Protocol Guardian v2 — Multi-Protocol Watchlist")
    print("=" * 55)

    wl = Watchlist()

    # Add major protocols
    for pid in ["aave_v3", "uniswap_v3", "compound_v3", "makerdao", "lido", "wormhole"]:
        wl.add_from_registry(pid)

    status = wl.get_status()
    print(f"\nActive Protocols: {status['active_protocols']}")
    print(f"Total Contracts:  {status['total_contracts']}")
    print(f"Total TVL:        {status['total_tvl_display']}")
    print(f"Chains:           {', '.join(status['chains'])}")

    print(f"\n{'Protocol':<25} {'Chain':<12} {'Category':<14} {'TVL':<10} {'Contracts':<10}")
    print("─" * 71)
    for p in status["protocols"]:
        print(f"{p['name']:<25} {p['chain']:<12} {p['category']:<14} {p['tvl']:<10} {p['contracts']}")

    print(f"\nTotal watched addresses: {len(wl.get_all_addresses())}")
    print(f"Total critical selectors: {len(wl.get_all_selectors())}")

    # Test lookup
    print(f"\nLookup 0x8787...4e2: {wl.get_contract_label('0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2')}")
    print(f"Lookup 0x8456...630E: {wl.get_contract_label('0x84568d45c653844BAe9d459311dD3487FcA2630E')}")

    print("\n─── Full Registry ───")
    for entry in wl.get_registry_status():
        status_icon = "✅" if entry["active"] else "⬚"
        print(f"  {status_icon} {entry['name']:<25} {entry['chain']:<10} {entry['tvl']:<10}")
