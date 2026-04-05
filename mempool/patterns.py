"""
Protocol Guardian v2 — Exploit Pattern Database
================================================
Function selectors, calldata signatures, and behavioral patterns
extracted from 400+ historical DeFi exploits (2020-2026).

Each pattern includes:
  - 4-byte function selector (first 4 bytes of keccak256 of signature)
  - Human-readable signature
  - Attack category
  - Risk weight (0.0 - 1.0)
  - Known exploit references
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AttackCategory(str, Enum):
    FLASH_LOAN = "flash_loan"
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ACCESS_CONTROL = "access_control"
    PRICE_MANIPULATION = "price_manipulation"
    GOVERNANCE_ATTACK = "governance_attack"
    FRONT_RUNNING = "front_running"
    SANDWICH = "sandwich_attack"
    RUGPULL = "rugpull"
    LOGIC_BUG = "logic_bug"


@dataclass
class ExploitSignature:
    """A single known exploit function signature."""
    selector: str           # 0xabcdef12
    signature: str          # functionName(type1,type2)
    category: AttackCategory
    risk_weight: float      # 0.0 to 1.0
    description: str
    references: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────
# Flash Loan Function Selectors
# Source: Aave, dYdX, Uniswap, Balancer flash loan interfaces
# ─────────────────────────────────────────────────────────

FLASH_LOAN_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0xab9c4b5d",
        signature="flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.7,
        description="Aave V3 flash loan — borrows multiple assets atomically",
        references=["Euler Finance ($197M)", "Cream Finance ($130M)"],
    ),
    ExploitSignature(
        selector="0x5cffe9de",
        signature="flashLoan(address,address,uint256,bytes)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.7,
        description="Aave V2 / generic ERC-3156 flash loan",
        references=["bZx ($8M)", "Harvest Finance ($34M)"],
    ),
    ExploitSignature(
        selector="0x490e6cbc",
        signature="flashLoan(address,address[],uint256[],bytes)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.7,
        description="Balancer flash loan — multi-token",
        references=["Balancer pool exploits"],
    ),
    ExploitSignature(
        selector="0xd9d98ce4",
        signature="flashFee(address,uint256)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.3,
        description="ERC-3156 fee query — indicates flash loan setup",
    ),
    ExploitSignature(
        selector="0x613255ab",
        signature="maxFlashLoan(address)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.2,
        description="ERC-3156 max loan query — reconnaissance phase",
    ),
    ExploitSignature(
        selector="0xc3924ed6",
        signature="swap(uint256,uint256,address,bytes)",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.5,
        description="Uniswap V2 swap with callback (flash swap)",
        references=["PancakeBunny ($45M)"],
    ),
]


# ─────────────────────────────────────────────────────────
# Reentrancy Indicators
# Pattern: External calls before state updates
# ─────────────────────────────────────────────────────────

REENTRANCY_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0x3ccfd60b",
        signature="withdraw()",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.4,
        description="Parameterless withdraw — classic reentrancy target",
        references=["The DAO ($60M)", "Siren Protocol ($3.5M)"],
    ),
    ExploitSignature(
        selector="0x2e1a7d4d",
        signature="withdraw(uint256)",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.4,
        description="Amount-based withdraw — check state update ordering",
        references=["Lendf.me ($25M)"],
    ),
    ExploitSignature(
        selector="0x853828b6",
        signature="withdrawAll()",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.5,
        description="Full balance withdraw — high-value reentrancy target",
    ),
    ExploitSignature(
        selector="0x441a3e70",
        signature="withdraw(uint256,uint256)",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.4,
        description="Pool/amount withdraw — LP reentrancy vector",
        references=["Curve read-only reentrancy"],
    ),
    ExploitSignature(
        selector="0xe9fad8ee",
        signature="exit()",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.5,
        description="Full exit function — unstake + withdraw combined",
    ),
    ExploitSignature(
        selector="0xdb006a75",
        signature="redeem(uint256)",
        category=AttackCategory.REENTRANCY,
        risk_weight=0.4,
        description="Token redemption — Compound-style cToken redeem",
        references=["Hundred Finance ($7M)"],
    ),
]


# ─────────────────────────────────────────────────────────
# Oracle / Price Manipulation
# ─────────────────────────────────────────────────────────

ORACLE_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0xfeaf968c",
        signature="latestRoundData()",
        category=AttackCategory.ORACLE_MANIPULATION,
        risk_weight=0.3,
        description="Chainlink oracle read — check for stale data usage",
        references=["Bonq DAO ($120M)"],
    ),
    ExploitSignature(
        selector="0x50d25bcd",
        signature="latestAnswer()",
        category=AttackCategory.ORACLE_MANIPULATION,
        risk_weight=0.4,
        description="Deprecated Chainlink read — no staleness check",
    ),
    ExploitSignature(
        selector="0x0902f1ac",
        signature="getReserves()",
        category=AttackCategory.ORACLE_MANIPULATION,
        risk_weight=0.5,
        description="Uniswap V2 reserves query — spot price oracle (manipulable)",
        references=["Warp Finance ($7.7M)", "Cheese Bank ($3.3M)"],
    ),
    ExploitSignature(
        selector="0x5909c0d5",
        signature="price0CumulativeLast()",
        category=AttackCategory.ORACLE_MANIPULATION,
        risk_weight=0.3,
        description="TWAP accumulator read — safer but can still be gamed",
    ),
    ExploitSignature(
        selector="0x252dba42",
        signature="aggregate((address,bytes)[])",
        category=AttackCategory.ORACLE_MANIPULATION,
        risk_weight=0.3,
        description="Multicall aggregate — batch price queries (recon phase)",
    ),
]


# ─────────────────────────────────────────────────────────
# Access Control / Privilege Escalation
# ─────────────────────────────────────────────────────────

ACCESS_CONTROL_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0xf2fde38b",
        signature="transferOwnership(address)",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.9,
        description="Ownership transfer — critical if called by non-owner",
        references=["Poly Network ($611M)"],
    ),
    ExploitSignature(
        selector="0x3659cfe6",
        signature="upgradeTo(address)",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.95,
        description="Proxy upgrade — replaces entire contract logic",
        references=["Nomad Bridge ($190M)", "Ronin Bridge ($624M)"],
    ),
    ExploitSignature(
        selector="0x4f1ef286",
        signature="upgradeToAndCall(address,bytes)",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.95,
        description="Proxy upgrade + initialization — highest severity",
        references=["Wormhole ($326M)"],
    ),
    ExploitSignature(
        selector="0x2f2ff15d",
        signature="grantRole(bytes32,address)",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.8,
        description="Role grant — privilege escalation if unauthorized",
    ),
    ExploitSignature(
        selector="0x8456cb59",
        signature="pause()",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.6,
        description="Emergency pause — may indicate insider threat or response",
    ),
    ExploitSignature(
        selector="0x715018a6",
        signature="renounceOwnership()",
        category=AttackCategory.ACCESS_CONTROL,
        risk_weight=0.7,
        description="Ownership renouncement — can be used to lock funds",
    ),
]


# ─────────────────────────────────────────────────────────
# DEX / Price Manipulation Patterns
# ─────────────────────────────────────────────────────────

PRICE_MANIPULATION_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0x022c0d9f",
        signature="swap(uint256,uint256,address,bytes)",
        category=AttackCategory.PRICE_MANIPULATION,
        risk_weight=0.5,
        description="Uniswap V2 swap — large swaps can manipulate price",
        references=["Numerous sandwich attacks"],
    ),
    ExploitSignature(
        selector="0x128acb08",
        signature="swap(address,bool,int256,uint160,bytes)",
        category=AttackCategory.PRICE_MANIPULATION,
        risk_weight=0.5,
        description="Uniswap V3 swap — concentrated liquidity manipulation",
    ),
    ExploitSignature(
        selector="0x7c025200",
        signature="swap(address,(address,address,address,address,uint256,uint256,uint256),bytes,bytes)",
        category=AttackCategory.PRICE_MANIPULATION,
        risk_weight=0.4,
        description="1inch aggregated swap — large cross-DEX trades",
    ),
    ExploitSignature(
        selector="0xc6a68747",
        signature="addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256)",
        category=AttackCategory.PRICE_MANIPULATION,
        risk_weight=0.3,
        description="Add liquidity — can set up manipulation if paired with swap",
    ),
    ExploitSignature(
        selector="0xbaa2abde",
        signature="removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
        category=AttackCategory.PRICE_MANIPULATION,
        risk_weight=0.5,
        description="Remove liquidity — combined with swap = sandwich",
    ),
]


# ─────────────────────────────────────────────────────────
# Governance Attack Patterns
# ─────────────────────────────────────────────────────────

GOVERNANCE_SELECTORS: list[ExploitSignature] = [
    ExploitSignature(
        selector="0xda95691a",
        signature="propose(address[],uint256[],string[],bytes[],string)",
        category=AttackCategory.GOVERNANCE_ATTACK,
        risk_weight=0.6,
        description="Governance proposal — check for flash-loan funded voting",
        references=["Beanstalk ($182M)"],
    ),
    ExploitSignature(
        selector="0x56781388",
        signature="castVote(uint256,uint8)",
        category=AttackCategory.GOVERNANCE_ATTACK,
        risk_weight=0.3,
        description="Vote cast — suspicious if from new/flash-funded address",
    ),
    ExploitSignature(
        selector="0xfe0d94c1",
        signature="execute(uint256)",
        category=AttackCategory.GOVERNANCE_ATTACK,
        risk_weight=0.7,
        description="Execute governance proposal — critical if just proposed",
    ),
    ExploitSignature(
        selector="0x2364f1b9",
        signature="queue(uint256)",
        category=AttackCategory.GOVERNANCE_ATTACK,
        risk_weight=0.4,
        description="Queue proposal for execution — timelock bypass check",
    ),
]


# ─────────────────────────────────────────────────────────
# Aggregate all patterns into a lookup table
# ─────────────────────────────────────────────────────────

ALL_SIGNATURES: list[ExploitSignature] = (
    FLASH_LOAN_SELECTORS
    + REENTRANCY_SELECTORS
    + ORACLE_SELECTORS
    + ACCESS_CONTROL_SELECTORS
    + PRICE_MANIPULATION_SELECTORS
    + GOVERNANCE_SELECTORS
)

# Fast lookup: selector → ExploitSignature
SELECTOR_INDEX: dict[str, ExploitSignature] = {
    sig.selector.lower(): sig for sig in ALL_SIGNATURES
}


def match_selector(calldata: str) -> Optional[ExploitSignature]:
    """Match the first 4 bytes of calldata against known exploit signatures."""
    if not calldata or len(calldata) < 10:
        return None
    selector = calldata[:10].lower()
    return SELECTOR_INDEX.get(selector)


def match_all_selectors(calldata: str) -> list[ExploitSignature]:
    """
    Scan entire calldata for embedded selectors (nested calls).
    Attackers often encode multiple exploit calls in a single tx.
    """
    if not calldata or len(calldata) < 10:
        return []

    matches = []
    data = calldata.lower()

    # Primary selector
    primary = SELECTOR_INDEX.get(data[:10])
    if primary:
        matches.append(primary)

    # Scan for embedded selectors in the calldata payload
    # (common in multicall, batch, and flash loan callback data)
    for i in range(10, len(data) - 8, 2):
        candidate = "0x" + data[i : i + 8]
        sig = SELECTOR_INDEX.get(candidate)
        if sig and sig not in matches:
            matches.append(sig)

    return matches


# ─────────────────────────────────────────────────────────
# Behavioral heuristics (not just selector-based)
# ─────────────────────────────────────────────────────────

@dataclass
class BehavioralPattern:
    """Patterns detected from transaction metadata, not just calldata."""
    name: str
    description: str
    category: AttackCategory
    risk_weight: float


BEHAVIORAL_PATTERNS: list[BehavioralPattern] = [
    BehavioralPattern(
        name="high_gas_priority",
        description="Gas price >3x current base fee — front-running or MEV extraction",
        category=AttackCategory.FRONT_RUNNING,
        risk_weight=0.4,
    ),
    BehavioralPattern(
        name="contract_creation_and_call",
        description="New contract deployed and immediately called — attack contract pattern",
        category=AttackCategory.LOGIC_BUG,
        risk_weight=0.7,
    ),
    BehavioralPattern(
        name="large_value_transfer",
        description="Transaction value >100 ETH to a watched contract",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.5,
    ),
    BehavioralPattern(
        name="new_address_interaction",
        description="Address with <5 transactions interacting with high-TVL protocol",
        category=AttackCategory.LOGIC_BUG,
        risk_weight=0.3,
    ),
    BehavioralPattern(
        name="self_destruct_target",
        description="Transaction targets a contract that recently self-destructed",
        category=AttackCategory.RUGPULL,
        risk_weight=0.9,
    ),
    BehavioralPattern(
        name="rapid_multi_protocol",
        description="Same address hitting 3+ DeFi protocols within 2 blocks",
        category=AttackCategory.FLASH_LOAN,
        risk_weight=0.6,
    ),
    BehavioralPattern(
        name="sandwich_bracket",
        description="Two txs from same address bracketing a victim tx on same pair",
        category=AttackCategory.SANDWICH,
        risk_weight=0.8,
    ),
]
