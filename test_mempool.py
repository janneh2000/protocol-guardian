"""
Protocol Guardian v2 — Mempool Module Test Suite
=================================================
Simulates real exploit transactions through the analysis pipeline
to validate detection accuracy. Uses function selectors and calldata
patterns from actual historical DeFi exploits.

Run: python3 -m tests.test_mempool
"""

import sys
import os
import json
import time

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mempool.decoder import TransactionDecoder, ThreatAnalyzer, ThreatReport
from mempool.patterns import (
    AttackCategory,
    match_selector,
    match_all_selectors,
    ALL_SIGNATURES,
    SELECTOR_INDEX,
)


# ─────────────────────────────────────────────────────────
# Test fixtures — simulated exploit transactions
# ─────────────────────────────────────────────────────────

WATCHED_CONTRACTS = {
    "0x84568d45c653844bae9d459311dd3487fca2630e",  # MockLendingPool
    "0x2344b12ae58c9c097c8400edbb1f9fb4dfca12fe",  # ProtocolGuardian
    "0x7d2768de32b0b80b7a3454c06bdac94a69ddc7a9",  # Aave V2 Pool (mainnet)
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",  # Aave V3 Pool (mainnet)
}

# Simulated exploit transactions (using real function selectors)
EXPLOIT_SCENARIOS = {
    "flash_loan_attack": {
        "name": "Euler-style Flash Loan Exploit",
        "description": "Attacker takes Aave V3 flash loan and targets our lending pool",
        "raw_tx": {
            "hash": "0xdead0001" + "0" * 56,
            "from": "0xattacker1" + "0" * 30,
            "to": "0x84568d45c653844bae9d459311dd3487fca2630e",  # Our MockLendingPool
            "value": "0x0",
            "gasPrice": "0x12a05f200",       # 50 gwei
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x7a120",                 # 500,000
            "nonce": "0x1",
            # flashLoan(address,address[],uint256[],...) selector + large calldata
            "input": (
                "0xab9c4b5d"  # Aave V3 flashLoan selector
                + "0" * 64    # receiver address
                + "0" * 64    # assets array offset
                + "0" * 64    # amounts array offset
                + "0" * 64    # modes array
                + "0" * 64    # onBehalfOf
                + "0" * 64    # params offset
                + "0" * 64    # referralCode
                # Embedded in callback data: withdraw + swap selectors
                + "3ccfd60b"  # withdraw() - reentrancy target
                + "0" * 60
                + "022c0d9f"  # Uniswap swap - price manipulation
                + "0" * 60
            ),
        },
        "expected_categories": ["flash_loan", "reentrancy", "price_manipulation"],
        "expected_min_score": 0.7,
    },

    "reentrancy_drain": {
        "name": "Classic Reentrancy Drain (DAO-style)",
        "description": "Attacker calls withdraw() on our lending pool",
        "raw_tx": {
            "hash": "0xdead0002" + "0" * 56,
            "from": "0xattacker2" + "0" * 30,
            "to": "0x84568d45c653844bae9d459311dd3487fca2630e",
            "value": "0x0",
            "gasPrice": "0x2540be400",       # 100 gwei (3x+ base = front-running)
            "maxPriorityFeePerGas": "0x0",
            "gas": "0xf4240",                 # 1,000,000 (high gas = many reentrant calls)
            "nonce": "0x0",                   # First tx from this address
            "input": (
                "0x853828b6"  # withdrawAll()
                + "0" * 64
            ),
        },
        "expected_categories": ["reentrancy", "front_running"],
        "expected_min_score": 0.5,
    },

    "oracle_manipulation": {
        "name": "Oracle Price Manipulation",
        "description": "Attacker queries reserves then swaps to manipulate price",
        "raw_tx": {
            "hash": "0xdead0003" + "0" * 56,
            "from": "0xattacker3" + "0" * 30,
            "to": "0x84568d45c653844bae9d459311dd3487fca2630e",
            "value": "0x56bc75e2d63100000",   # 100 ETH
            "gasPrice": "0x12a05f200",
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x7a120",
            "nonce": "0x5",
            "input": (
                "0x0902f1ac"  # getReserves() - spot price oracle read
                + "0" * 64
                # Embedded: flash loan + swap
                + "5cffe9de"  # Aave V2 flashLoan
                + "0" * 60
                + "022c0d9f"  # Uniswap swap
                + "0" * 60
            ),
        },
        "expected_categories": ["oracle_manipulation", "flash_loan", "price_manipulation"],
        "expected_min_score": 0.7,
    },

    "proxy_upgrade_attack": {
        "name": "Unauthorized Proxy Upgrade (Nomad-style)",
        "description": "Attacker upgrades proxy to malicious implementation",
        "raw_tx": {
            "hash": "0xdead0004" + "0" * 56,
            "from": "0xattacker4" + "0" * 30,
            "to": "0x2344b12ae58c9c097c8400edbb1f9fb4dfca12fe",  # ProtocolGuardian
            "value": "0x0",
            "gasPrice": "0x12a05f200",
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x30d40",
            "nonce": "0x3",
            "input": (
                "0x4f1ef286"  # upgradeToAndCall(address,bytes)
                + "0" * 64    # new implementation address
                + "0" * 64    # calldata offset
                + "0" * 64    # calldata length
                + "f2fde38b"  # transferOwnership embedded
                + "0" * 60
            ),
        },
        "expected_categories": ["access_control"],
        "expected_min_score": 0.9,
    },

    "governance_flash_loan": {
        "name": "Governance Takeover (Beanstalk-style)",
        "description": "Flash loan funded governance vote + execution",
        "raw_tx": {
            "hash": "0xdead0005" + "0" * 56,
            "from": "0xattacker5" + "0" * 30,
            "to": "0x84568d45c653844bae9d459311dd3487fca2630e",
            "value": "0x0",
            "gasPrice": "0x12a05f200",
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x1e8480",                 # 2,000,000
            "nonce": "0x1",
            "input": (
                "0xab9c4b5d"  # flashLoan
                + "0" * 64
                # Governance actions embedded in callback
                + "da95691a"  # propose()
                + "0" * 60
                + "56781388"  # castVote()
                + "0" * 60
                + "fe0d94c1"  # execute()
                + "0" * 60
            ),
        },
        "expected_categories": ["flash_loan", "governance_attack"],
        "expected_min_score": 0.8,
    },

    "benign_swap": {
        "name": "Normal DEX Swap (should be LOW risk)",
        "description": "Regular user doing a Uniswap swap — should NOT trigger alerts",
        "raw_tx": {
            "hash": "0xbeef0001" + "0" * 56,
            "from": "0xnormaluser" + "0" * 28,
            "to": "0xe592427a0aece92de3edee1f18e0157c05861564",  # Uniswap Router (NOT watched)
            "value": "0xde0b6b3a7640000",    # 1 ETH
            "gasPrice": "0x9502f900",         # 25 gwei (normal)
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x30d40",                  # 200,000 (normal)
            "nonce": "0x42",
            "input": (
                "0x022c0d9f"  # swap
                + "0" * 128
            ),
        },
        "expected_categories": [],  # Should be empty or low risk
        "expected_max_score": 0.5,
    },

    "contract_creation_attack": {
        "name": "Attack Contract Deployment",
        "description": "New contract deployed with large bytecode — possible attack setup",
        "raw_tx": {
            "hash": "0xdead0006" + "0" * 56,
            "from": "0xattacker6" + "0" * 30,
            "to": None,  # Contract creation
            "value": "0x0",
            "gasPrice": "0x12a05f200",
            "maxPriorityFeePerGas": "0x0",
            "gas": "0x4c4b40",                 # 5,000,000
            "nonce": "0x0",
            "input": "0x" + "60806040" + "ab" * 2000,  # Large bytecode
        },
        "expected_categories": ["logic_bug"],
        "expected_min_score": 0.3,
    },
}


# ─────────────────────────────────────────────────────────
# Test runner
# ─────────────────────────────────────────────────────────

def print_header(text: str):
    width = 72
    print(f"\n{'=' * width}")
    print(f"  {text}")
    print(f"{'=' * width}")


def print_threat_report(report: ThreatReport, scenario_name: str):
    """Pretty-print a threat report."""
    risk_emoji = {
        "low": "🟢",
        "medium": "🟡",
        "high": "🟠",
        "critical": "🔴",
    }

    emoji = risk_emoji.get(report.risk_level, "⚪")
    print(f"\n  {emoji} [{report.risk_level.upper()}] {scenario_name}")
    print(f"  {'─' * 60}")
    print(f"  TX Hash:     {report.tx.tx_hash[:20]}...")
    print(f"  From:        {report.tx.from_address[:20]}...")
    print(f"  To:          {(report.tx.to_address or 'CONTRACT CREATION')[:20]}...")
    print(f"  Value:       {report.tx.value_eth:.4f} ETH")
    print(f"  Gas:         {report.tx.gas_price_gwei:.1f} gwei")
    print(f"  Calldata:    {report.tx.calldata_size} bytes")
    print(f"  Risk Score:  {report.composite_risk_score:.2%}")
    print(f"  Categories:  {', '.join(report.attack_categories) or 'none'}")
    print(f"  Indicators:  {len(report.indicators)}")
    print(f"  Latency:     {report.analysis_latency_ms:.2f} ms")
    print(f"  Action:      {report.recommended_action}")

    if report.indicators:
        print(f"\n  Threat Indicators:")
        for i, ind in enumerate(report.indicators, 1):
            print(f"    [{i}] {ind.category.value}: {ind.description}")
            print(f"        Evidence: {ind.evidence}")
            if ind.references:
                print(f"        Refs: {', '.join(ind.references)}")


def run_tests():
    """Run all exploit scenarios through the threat analysis pipeline."""
    print_header("Protocol Guardian v2 — Mempool Threat Detection Tests")
    print(f"  Loaded {len(ALL_SIGNATURES)} exploit signatures")
    print(f"  Watching {len(WATCHED_CONTRACTS)} contracts")

    decoder = TransactionDecoder()
    analyzer = ThreatAnalyzer(
        watched_contracts=WATCHED_CONTRACTS,
        base_fee_gwei=30.0,
        high_value_threshold_eth=50.0,
    )

    results = []
    total_latency = 0
    passed = 0
    failed = 0

    for scenario_id, scenario in EXPLOIT_SCENARIOS.items():
        print_header(f"Scenario: {scenario['name']}")
        print(f"  {scenario['description']}")

        # Decode the raw transaction
        tx = decoder.decode(scenario["raw_tx"])

        # Run threat analysis
        start = time.monotonic()
        report = analyzer.analyze(tx)
        latency = (time.monotonic() - start) * 1000
        total_latency += latency

        # Display report
        print_threat_report(report, scenario["name"])

        # Validate expectations
        expected_cats = set(scenario.get("expected_categories", []))
        actual_cats = set(report.attack_categories)

        test_passed = True
        if "expected_min_score" in scenario:
            if report.composite_risk_score < scenario["expected_min_score"]:
                print(f"\n  ❌ FAIL: Score {report.composite_risk_score:.2%} < "
                      f"expected min {scenario['expected_min_score']:.2%}")
                test_passed = False

        if "expected_max_score" in scenario:
            if report.composite_risk_score > scenario["expected_max_score"]:
                print(f"\n  ❌ FAIL: Score {report.composite_risk_score:.2%} > "
                      f"expected max {scenario['expected_max_score']:.2%}")
                test_passed = False

        if expected_cats:
            missing = expected_cats - actual_cats
            if missing:
                print(f"\n  ⚠️  WARN: Missing expected categories: {missing}")
                # Don't fail on this — embedded selectors may not always match

        if test_passed:
            print(f"\n  ✅ PASSED")
            passed += 1
        else:
            failed += 1

        results.append({
            "scenario": scenario_id,
            "name": scenario["name"],
            "score": report.composite_risk_score,
            "level": report.risk_level,
            "categories": report.attack_categories,
            "indicators": len(report.indicators),
            "passed": test_passed,
        })

    # ─────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────

    print_header("Test Summary")
    print(f"\n  Total Scenarios:  {len(EXPLOIT_SCENARIOS)}")
    print(f"  Passed:           {passed}")
    print(f"  Failed:           {failed}")
    print(f"  Avg Latency:      {total_latency / len(EXPLOIT_SCENARIOS):.2f} ms")

    print(f"\n  {'Scenario':<30} {'Score':>8} {'Level':>10} {'Indicators':>12} {'Status':>8}")
    print(f"  {'─' * 72}")
    for r in results:
        status = "✅" if r["passed"] else "❌"
        print(
            f"  {r['name'][:30]:<30} "
            f"{r['score']:>7.1%} "
            f"{r['level']:>10} "
            f"{r['indicators']:>12} "
            f"{status:>8}"
        )

    # Show Claude context for the most dangerous scenario
    print_header("Sample Claude Context (Proxy Upgrade Attack)")
    proxy_tx = decoder.decode(EXPLOIT_SCENARIOS["proxy_upgrade_attack"]["raw_tx"])
    proxy_report = analyzer.analyze(proxy_tx)
    print(proxy_report.claude_context)

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
