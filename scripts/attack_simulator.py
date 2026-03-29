"""
attack_simulator.py — Flash loan price manipulation simulator.

This is the DEMO WEAPON. Run this while the guardian agent is running
to trigger a live detection event.

What it simulates:
  1. Take a flash loan from the lending pool
  2. Manipulate the oracle price downward (simulate thin-market attack)
  3. Attempt to borrow max against the manipulated collateral
  4. The guardian detects this in the mempool and calls pause()
  5. The borrow transaction REVERTS because the protocol is paused

Usage:
    python scripts/attack_simulator.py

Expected output:
  [ATTACKER] Flash loan sent: 0x...
  [GUARDIAN] Threat detected: flash_loan_price_manipulation (93% confidence)
  [GUARDIAN] Protocol PAUSED. Tx: 0x...
  [ATTACKER] Borrow attempt FAILED: execution reverted (Protocol is paused)
  [GUARDIAN] Post-incident report generated.
"""

import json
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

load_dotenv(Path(__file__).parent.parent / ".env")

RPC = os.environ["ALCHEMY_HTTP_RPC"]
ATTACKER_KEY = os.environ.get("ATTACKER_PRIVATE_KEY", os.environ.get("DEPLOYER_PRIVATE_KEY"))
POOL_ADDRESS = os.environ["LENDING_POOL_ADDRESS"]

w3 = Web3(Web3.HTTPProvider(RPC))

abi_path = Path(__file__).parent.parent / "abi" / "MockLendingPool.json"
with open(abi_path) as f:
    POOL_ABI = json.load(f)

pool = w3.eth.contract(address=Web3.to_checksum_address(POOL_ADDRESS), abi=POOL_ABI)
attacker = w3.eth.account.from_key(ATTACKER_KEY)


def send_tx(fn_call, value=0, label="tx"):
    nonce = w3.eth.get_transaction_count(attacker.address)
    gas_price = w3.eth.gas_price
    txn = fn_call.build_transaction({
        "from": attacker.address,
        "nonce": nonce,
        "value": value,
        "gasPrice": gas_price,
        "gas": 500000,
    })
    signed = w3.eth.account.sign_transaction(txn, attacker.key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    hex_hash = "0x" + tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash
    print(f"[ATTACKER] {label}: {hex_hash}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    status = "SUCCESS" if receipt.status == 1 else "REVERTED"
    print(f"[ATTACKER] {label} {status} (block {receipt.blockNumber})")
    return receipt, hex_hash


def print_pool_state(label="Pool state"):
    liquidity, price, paused = pool.functions.getPoolStats().call()
    print(f"\n  [{label}]")
    print(f"  Liquidity: {w3.from_wei(liquidity, 'ether'):.6f} ETH")
    print(f"  Price:     ${price / 1e18:,.2f}")
    print(f"  Paused:    {paused}")


def main():
    print("\n" + "="*60)
    print("  PROTOCOL GUARDIAN — ATTACK SIMULATOR")
    print("  Simulating: Flash Loan + Oracle Manipulation")
    print("="*60)

    # Check attacker balance
    bal = w3.eth.get_balance(attacker.address)
    print(f"\nAttacker address: {attacker.address}")
    print(f"Attacker balance: {w3.from_wei(bal, 'ether'):.6f} ETH")

    if bal < w3.to_wei(0.01, "ether"):
        print("\n[ERROR] Attacker needs at least 0.01 ETH on Sepolia.")
        print("Get free Sepolia ETH: https://sepoliafaucet.com/")
        sys.exit(1)

    print_pool_state("Before attack")

    print("\n[ATTACKER] Phase 1 — Manipulating oracle price...")
    print("[ATTACKER] Sending price manipulation tx to mempool...")
    print("[ATTACKER] (Guardian should detect this before it confirms)\n")
    print(">> Waiting 3 seconds for guardian to detect in mempool...\n")
    time.sleep(3)

    # Step 1: Manipulate oracle price (crash by 50%)
    # This triggers the oracle_price_update heuristic
    new_price = int(1000 * 1e18)  # Crash from $2000 → $1000
    try:
        receipt, hash1 = send_tx(
            pool.functions.updatePrice(new_price),
            label="Oracle manipulation (price $2000 -> $1000)"
        )
    except Exception as e:
        if "paused" in str(e).lower() or "execution reverted" in str(e).lower():
            print(f"\n[!] Oracle update REVERTED — protocol may already be paused!")
            print_pool_state("After attempted attack")
            return
        raise

    print_pool_state("After oracle manipulation")

    # Step 2: Attempt flash loan + borrow (should be caught or fail if paused)
    print("\n[ATTACKER] Phase 2 — Attempting flash loan drain...")
    pool_balance = pool.functions.totalLiquidity().call()
    if pool_balance == 0:
        print("[ATTACKER] Pool has no liquidity to flash loan. Seeding first...")
        # Can't drain what's not there; this is expected in fresh deploy
        print("[ATTACKER] Attack complete (nothing to drain).")
        return

    borrow_amount = min(pool_balance // 2, w3.to_wei(0.04, "ether"))
    print(f"[ATTACKER] Attempting to borrow {w3.from_wei(borrow_amount, 'ether'):.4f} ETH...")

    try:
        receipt, hash2 = send_tx(
            pool.functions.borrow(borrow_amount),
            label="Borrow (exploit attempt)"
        )
        if receipt.status == 0:
            print("\n[ATTACKER] Borrow REVERTED — Guardian successfully paused the protocol!")
        else:
            print("\n[WARNING] Borrow succeeded — Guardian may not have responded in time.")
    except Exception as e:
        if "paused" in str(e).lower() or "Pausable" in str(e):
            print("\n[ATTACKER] Borrow FAILED: Protocol is PAUSED!")
            print("[GUARDIAN] Attack neutralised successfully.")
        else:
            print(f"\n[ATTACKER] Borrow failed with: {e}")

    print_pool_state("After attack attempt")

    print("\n" + "="*60)
    print("  SIMULATION COMPLETE")
    print("  Check your guardian terminal for AI analysis output")
    print("  Check dashboard/events.json for the event log")
    print("  Check dashboard/last_report.json for the incident report")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
