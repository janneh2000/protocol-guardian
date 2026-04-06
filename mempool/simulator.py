"""
Protocol Guardian v2 — EVM Trace Simulator
============================================
Simulates suspicious pending transactions using eth_call BEFORE
they land on-chain. Extracts:
  - Internal call traces (CALL, DELEGATECALL, STATICCALL)
  - State diffs (storage slot changes)
  - Token transfer events (ERC-20 Transfer logs)
  - ETH value flows between addresses
  - Gas consumption analysis

This gives Claude concrete EVIDENCE of what a transaction would
do — not just pattern matching, but actual proof.

Architecture:
  Pending TX → eth_call (simulate) → trace_call (debug) → Decode → Evidence Report → Claude
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger("guardian.simulator")


# ─────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────

class CallType(str, Enum):
    CALL = "CALL"
    DELEGATECALL = "DELEGATECALL"
    STATICCALL = "STATICCALL"
    CREATE = "CREATE"
    CREATE2 = "CREATE2"
    SELFDESTRUCT = "SELFDESTRUCT"


@dataclass
class InternalCall:
    """A single internal call within a transaction trace."""
    call_type: str
    from_addr: str
    to_addr: str
    value_wei: int
    value_eth: float
    gas_used: int
    input_data: str
    output_data: str
    selector: str
    depth: int
    error: Optional[str] = None

    @property
    def is_value_transfer(self) -> bool:
        return self.value_wei > 0

    @property
    def is_delegate(self) -> bool:
        return self.call_type == "DELEGATECALL"


@dataclass
class TokenTransfer:
    """An ERC-20 Transfer event decoded from simulation logs."""
    token_address: str
    from_addr: str
    to_addr: str
    amount_raw: int
    amount_display: str
    token_symbol: Optional[str] = None


@dataclass
class StateDiff:
    """A storage slot change detected in simulation."""
    contract: str
    slot: str
    old_value: str
    new_value: str


@dataclass
class SimulationResult:
    """Complete result of simulating a pending transaction."""
    tx_hash: str
    success: bool
    gas_used: int
    gas_limit: int
    return_data: str
    error: Optional[str]
    internal_calls: list[InternalCall]
    token_transfers: list[TokenTransfer]
    state_diffs: list[StateDiff]
    eth_flows: list[dict]  # {"from": addr, "to": addr, "value_eth": float}
    simulation_time_ms: float
    warnings: list[str]

    @property
    def total_eth_moved(self) -> float:
        return sum(f["value_eth"] for f in self.eth_flows)

    @property
    def unique_contracts_touched(self) -> int:
        addrs = set()
        for c in self.internal_calls:
            addrs.add(c.from_addr)
            addrs.add(c.to_addr)
        return len(addrs)

    @property
    def has_delegate_calls(self) -> bool:
        return any(c.is_delegate for c in self.internal_calls)

    @property
    def has_self_destruct(self) -> bool:
        return any(c.call_type == "SELFDESTRUCT" for c in self.internal_calls)

    @property
    def max_call_depth(self) -> int:
        return max((c.depth for c in self.internal_calls), default=0)

    def to_claude_context(self) -> str:
        """Format simulation results as structured context for Claude."""
        lines = [
            "=== EVM TRANSACTION SIMULATION RESULTS ===",
            f"TX Hash: {self.tx_hash}",
            f"Simulation Status: {'SUCCESS' if self.success else 'REVERTED'}",
            f"Gas Used: {self.gas_used:,} / {self.gas_limit:,} ({self.gas_used/max(self.gas_limit,1)*100:.1f}%)",
            f"Simulation Time: {self.simulation_time_ms:.1f}ms",
            "",
        ]

        if self.error:
            lines.append(f"Revert Reason: {self.error}")
            lines.append("")

        # Internal calls
        if self.internal_calls:
            lines.append(f"=== INTERNAL CALL TRACE ({len(self.internal_calls)} calls) ===")
            for i, call in enumerate(self.internal_calls):
                indent = "  " * call.depth
                value_str = f" [{call.value_eth:.4f} ETH]" if call.is_value_transfer else ""
                error_str = f" ⚠ {call.error}" if call.error else ""
                lines.append(
                    f"  {indent}[{i}] {call.call_type} {call.from_addr[:10]}→{call.to_addr[:10]} "
                    f"selector={call.selector}{value_str} gas={call.gas_used:,}{error_str}"
                )
            lines.append("")

        # Token transfers
        if self.token_transfers:
            lines.append(f"=== TOKEN TRANSFERS ({len(self.token_transfers)}) ===")
            for t in self.token_transfers:
                symbol = t.token_symbol or t.token_address[:10]
                lines.append(f"  {symbol}: {t.from_addr[:10]}→{t.to_addr[:10]} amount={t.amount_display}")
            lines.append("")

        # ETH flows
        if self.eth_flows:
            lines.append(f"=== ETH VALUE FLOWS ({len(self.eth_flows)} transfers, {self.total_eth_moved:.4f} ETH total) ===")
            for f in self.eth_flows:
                lines.append(f"  {f['from'][:10]}→{f['to'][:10]}: {f['value_eth']:.4f} ETH")
            lines.append("")

        # State diffs
        if self.state_diffs:
            lines.append(f"=== STATE CHANGES ({len(self.state_diffs)} slots modified) ===")
            for d in self.state_diffs:
                lines.append(f"  {d.contract[:10]} slot={d.slot[:18]}... {d.old_value[:18]}→{d.new_value[:18]}")
            lines.append("")

        # Warnings
        if self.warnings:
            lines.append("=== SIMULATION WARNINGS ===")
            for w in self.warnings:
                lines.append(f"  ⚠ {w}")
            lines.append("")

        # Summary stats
        lines.extend([
            "=== SIMULATION SUMMARY ===",
            f"Contracts touched: {self.unique_contracts_touched}",
            f"Max call depth: {self.max_call_depth}",
            f"Has DELEGATECALL: {self.has_delegate_calls}",
            f"Has SELFDESTRUCT: {self.has_self_destruct}",
            f"Total ETH moved: {self.total_eth_moved:.4f}",
            f"Token transfers: {len(self.token_transfers)}",
            "",
            "=== INSTRUCTION ===",
            "Analyze the simulation trace above. Look for:",
            "1. Unexpected DELEGATECALL to unknown contracts (proxy manipulation)",
            "2. Large token transfers to the tx sender (drain)",
            "3. Deep call chains with value flowing back to origin (reentrancy loop)",
            "4. SELFDESTRUCT calls (destructive attack)",
            "5. State changes to access control slots (privilege escalation)",
        ])

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────
# ERC-20 Transfer event decoding
# ─────────────────────────────────────────────────────────

# Transfer(address,address,uint256) event signature
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def decode_transfer_log(log: dict) -> Optional[TokenTransfer]:
    """Decode an ERC-20 Transfer event from a log entry."""
    topics = log.get("topics", [])
    if not topics or topics[0] != TRANSFER_TOPIC:
        return None
    if len(topics) < 3:
        return None

    try:
        from_addr = "0x" + topics[1][-40:]
        to_addr = "0x" + topics[2][-40:]
        data = log.get("data", "0x")
        amount_raw = int(data, 16) if data != "0x" else 0

        # Format amount (assume 18 decimals as default)
        amount_display = f"{amount_raw / 1e18:.6f}"

        return TokenTransfer(
            token_address=log.get("address", ""),
            from_addr=from_addr,
            to_addr=to_addr,
            amount_raw=amount_raw,
            amount_display=amount_display,
        )
    except (ValueError, IndexError):
        return None


# ─────────────────────────────────────────────────────────
# Simulator Engine
# ─────────────────────────────────────────────────────────

class EVMSimulator:
    """
    Simulates pending transactions using Ethereum JSON-RPC.

    Uses:
      - eth_call: Execute tx without committing (get return data + revert reason)
      - debug_traceCall: Full EVM trace with internal calls (Alchemy/Geth)
      - eth_estimateGas: Gas estimation as sanity check

    Falls back gracefully if debug APIs are unavailable.
    """

    def __init__(self, http_url: str):
        self.http_url = http_url
        self._session = None

    async def _get_session(self):
        if self._session is None:
            import aiohttp
            self._session = aiohttp.ClientSession()
        return self._session

    async def _rpc_call(self, method: str, params: list) -> dict:
        """Execute a JSON-RPC call."""
        session = await self._get_session()
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        async with session.post(
            self.http_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        ) as resp:
            return await resp.json()

    async def simulate(self, raw_tx: dict) -> SimulationResult:
        """
        Full simulation pipeline for a pending transaction.
        """
        start = time.monotonic()
        tx_hash = raw_tx.get("hash", "unknown")
        warnings = []

        # Build call object
        call_obj = {
            "from": raw_tx.get("from", "0x" + "0" * 40),
            "to": raw_tx.get("to"),
            "value": raw_tx.get("value", "0x0"),
            "data": raw_tx.get("input", "0x"),
            "gas": raw_tx.get("gas", "0x1e8480"),
        }

        gas_limit = int(raw_tx.get("gas", "0x1e8480"), 16)

        # ── Phase 1: eth_call (basic simulation) ──
        success = True
        return_data = "0x"
        error = None
        gas_used = 0

        try:
            result = await self._rpc_call("eth_call", [call_obj, "pending"])
            if "error" in result:
                success = False
                error = result["error"].get("message", "Unknown error")
                # Try to decode revert reason
                if "data" in result["error"]:
                    error = self._decode_revert(result["error"]["data"])
            else:
                return_data = result.get("result", "0x")
        except Exception as e:
            success = False
            error = str(e)
            warnings.append(f"eth_call failed: {e}")

        # ── Phase 2: Gas estimation ──
        try:
            gas_result = await self._rpc_call("eth_estimateGas", [call_obj])
            if "result" in gas_result:
                gas_used = int(gas_result["result"], 16)
        except Exception:
            gas_used = gas_limit  # Fallback

        # ── Phase 3: debug_traceCall (internal call trace) ──
        internal_calls = []
        token_transfers = []
        state_diffs = []
        eth_flows = []

        try:
            trace_result = await self._rpc_call("debug_traceCall", [
                call_obj,
                "pending",
                {"tracer": "callTracer", "tracerConfig": {"withLog": True}},
            ])

            if "result" in trace_result:
                trace = trace_result["result"]
                self._parse_trace(trace, internal_calls, eth_flows, token_transfers, depth=0)
        except Exception as e:
            # debug_traceCall may not be available on all nodes
            warnings.append(f"debug_traceCall unavailable: {e}. Using basic simulation only.")

            # Fallback: try alchemy_simulateExecution
            try:
                alchemy_result = await self._rpc_call("alchemy_simulateExecution", [call_obj])
                if "result" in alchemy_result:
                    self._parse_alchemy_sim(alchemy_result["result"], internal_calls, token_transfers, state_diffs)
            except Exception:
                warnings.append("alchemy_simulateExecution also unavailable. Trace data limited.")

        # ── Phase 4: Detect state diffs via debug_traceCall with prestateTracer ──
        if not state_diffs:
            try:
                prestate_result = await self._rpc_call("debug_traceCall", [
                    call_obj,
                    "pending",
                    {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}},
                ])
                if "result" in prestate_result:
                    self._parse_prestate_diff(prestate_result["result"], state_diffs)
            except Exception:
                pass  # State diffs are a bonus, not critical

        # ── Phase 5: Generate warnings ──
        if internal_calls:
            if any(c.call_type == "DELEGATECALL" for c in internal_calls):
                warnings.append("DELEGATECALL detected — execution context of calling contract used")
            if any(c.call_type == "SELFDESTRUCT" for c in internal_calls):
                warnings.append("SELFDESTRUCT detected — contract will be destroyed")
            if any(c.call_type in ("CREATE", "CREATE2") for c in internal_calls):
                warnings.append("New contract creation during execution — possible attack contract deployment")
            max_depth = max(c.depth for c in internal_calls)
            if max_depth >= 4:
                warnings.append(f"Deep call chain (depth={max_depth}) — possible reentrancy")

        if eth_flows:
            total = sum(f["value_eth"] for f in eth_flows)
            if total > 10:
                warnings.append(f"Large ETH movement: {total:.2f} ETH across {len(eth_flows)} transfers")

        sim_time = (time.monotonic() - start) * 1000

        return SimulationResult(
            tx_hash=tx_hash,
            success=success,
            gas_used=gas_used,
            gas_limit=gas_limit,
            return_data=return_data,
            error=error,
            internal_calls=internal_calls,
            token_transfers=token_transfers,
            state_diffs=state_diffs,
            eth_flows=eth_flows,
            simulation_time_ms=round(sim_time, 2),
            warnings=warnings,
        )

    def _parse_trace(
        self, trace: dict, calls: list, flows: list, transfers: list, depth: int
    ):
        """Recursively parse a callTracer result."""
        call_type = trace.get("type", "CALL").upper()
        from_addr = trace.get("from", "").lower()
        to_addr = trace.get("to", "").lower()
        value_hex = trace.get("value", "0x0")
        value_wei = int(value_hex, 16) if value_hex else 0
        input_data = trace.get("input", "0x")
        output_data = trace.get("output", "0x")
        gas_used = int(trace.get("gasUsed", "0x0"), 16)
        error = trace.get("error")

        selector = input_data[:10] if input_data and len(input_data) >= 10 else "0x"

        calls.append(InternalCall(
            call_type=call_type,
            from_addr=from_addr,
            to_addr=to_addr,
            value_wei=value_wei,
            value_eth=value_wei / 1e18,
            gas_used=gas_used,
            input_data=input_data[:66] if len(input_data) > 66 else input_data,  # Truncate for context
            output_data=output_data[:66] if len(output_data) > 66 else output_data,
            selector=selector,
            depth=depth,
            error=error,
        ))

        if value_wei > 0:
            flows.append({
                "from": from_addr,
                "to": to_addr,
                "value_eth": value_wei / 1e18,
            })

        # Parse logs for token transfers
        for log in trace.get("logs", []):
            transfer = decode_transfer_log(log)
            if transfer:
                transfers.append(transfer)

        # Recurse into subcalls
        for subcall in trace.get("calls", []):
            self._parse_trace(subcall, calls, flows, transfers, depth + 1)

    def _parse_alchemy_sim(self, result: dict, calls: list, transfers: list, diffs: list):
        """Parse Alchemy simulateExecution response."""
        for log in result.get("logs", []):
            transfer = decode_transfer_log(log)
            if transfer:
                transfers.append(transfer)

    def _parse_prestate_diff(self, result: dict, diffs: list):
        """Parse prestateTracer diff mode results."""
        post = result.get("post", {})
        pre = result.get("pre", {})

        for addr in set(list(post.keys()) + list(pre.keys())):
            post_storage = post.get(addr, {}).get("storage", {})
            pre_storage = pre.get(addr, {}).get("storage", {})
            all_slots = set(list(post_storage.keys()) + list(pre_storage.keys()))

            for slot in all_slots:
                old_val = pre_storage.get(slot, "0x0")
                new_val = post_storage.get(slot, "0x0")
                if old_val != new_val:
                    diffs.append(StateDiff(
                        contract=addr,
                        slot=slot,
                        old_value=old_val,
                        new_value=new_val,
                    ))

    def _decode_revert(self, data: str) -> str:
        """Try to decode a revert reason from error data."""
        if not data or len(data) < 10:
            return "Unknown revert"

        # Error(string) selector = 0x08c379a0
        if data.startswith("0x08c379a0") and len(data) > 138:
            try:
                # Decode the string from ABI encoding
                hex_str = data[138:]  # Skip selector + offset + length
                msg_bytes = bytes.fromhex(hex_str)
                return msg_bytes.decode("utf-8", errors="replace").rstrip("\x00")
            except Exception:
                pass

        # Panic(uint256) selector = 0x4e487b71
        if data.startswith("0x4e487b71") and len(data) >= 74:
            try:
                code = int(data[10:74], 16)
                panic_codes = {
                    0x00: "Generic compiler panic",
                    0x01: "Assert failed",
                    0x11: "Arithmetic overflow/underflow",
                    0x12: "Division by zero",
                    0x21: "Invalid enum value",
                    0x22: "Bad storage encoding",
                    0x31: "Array pop on empty",
                    0x32: "Array out of bounds",
                    0x41: "Too much memory",
                    0x51: "Zero-initialized function pointer",
                }
                return f"Panic: {panic_codes.get(code, f'code={code}')}"
            except Exception:
                pass

        return f"Revert: {data[:42]}..."

    async def close(self):
        """Clean up the HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None


# ─────────────────────────────────────────────────────────
# Simulation + local test mode (no RPC needed)
# ─────────────────────────────────────────────────────────

def create_mock_simulation(raw_tx: dict) -> SimulationResult:
    """
    Create a mock simulation result for testing/demo.
    Generates realistic trace data without calling an actual node.
    """
    tx_hash = raw_tx.get("hash", "0x" + "0" * 64)
    from_addr = raw_tx.get("from", "0x" + "0" * 40).lower()
    to_addr = (raw_tx.get("to") or "0x" + "0" * 40).lower()
    calldata = raw_tx.get("input", "0x")
    selector = calldata[:10] if len(calldata) >= 10 else "0x"
    value_wei = int(raw_tx.get("value", "0x0"), 16)

    internal_calls = [
        InternalCall(
            call_type="CALL", from_addr=from_addr, to_addr=to_addr,
            value_wei=value_wei, value_eth=value_wei/1e18, gas_used=45000,
            input_data=calldata[:66], output_data="0x", selector=selector, depth=0,
        ),
    ]

    # Simulate flash loan callback
    if "ab9c4b5d" in calldata or "5cffe9de" in calldata:
        internal_calls.extend([
            InternalCall(
                call_type="CALL", from_addr=to_addr, to_addr=from_addr,
                value_wei=int(50e18), value_eth=50.0, gas_used=21000,
                input_data="0xab9c4b5d", output_data="0x", selector="0xab9c4b5d", depth=1,
            ),
            InternalCall(
                call_type="CALL", from_addr=from_addr, to_addr=to_addr,
                value_wei=0, value_eth=0, gas_used=35000,
                input_data="0x3ccfd60b", output_data="0x", selector="0x3ccfd60b", depth=2,
                error=None,
            ),
            InternalCall(
                call_type="CALL", from_addr=from_addr, to_addr=to_addr,
                value_wei=0, value_eth=0, gas_used=35000,
                input_data="0x3ccfd60b", output_data="0x", selector="0x3ccfd60b", depth=2,
                error=None,
            ),
        ])

    # Simulate proxy upgrade
    if "4f1ef286" in calldata:
        internal_calls.append(
            InternalCall(
                call_type="DELEGATECALL", from_addr=to_addr, to_addr="0xdeadbeef" + "0" * 32,
                value_wei=0, value_eth=0, gas_used=28000,
                input_data="0xf2fde38b", output_data="0x", selector="0xf2fde38b", depth=1,
            ),
        )

    eth_flows = [{"from": f.from_addr, "to": f.to_addr, "value_eth": f.value_eth}
                 for f in internal_calls if f.value_eth > 0]

    warnings = []
    if any(c.call_type == "DELEGATECALL" for c in internal_calls):
        warnings.append("DELEGATECALL detected — proxy manipulation possible")
    max_depth = max(c.depth for c in internal_calls)
    if max_depth >= 2:
        warnings.append(f"Deep call chain (depth={max_depth}) — possible reentrancy pattern")

    return SimulationResult(
        tx_hash=tx_hash, success=True, gas_used=sum(c.gas_used for c in internal_calls),
        gas_limit=500000, return_data="0x", error=None,
        internal_calls=internal_calls, token_transfers=[], state_diffs=[],
        eth_flows=eth_flows, simulation_time_ms=1.5, warnings=warnings,
    )


if __name__ == "__main__":
    # Quick test with a mock flash loan tx
    mock_tx = {
        "hash": "0xdead" + "0" * 60,
        "from": "0xattacker" + "0" * 30,
        "to": "0x84568d45c653844bae9d459311dd3487fca2630e",
        "value": "0x0",
        "gas": "0x7a120",
        "input": "0xab9c4b5d" + "0" * 128 + "3ccfd60b" + "0" * 60,
    }
    result = create_mock_simulation(mock_tx)
    print(result.to_claude_context())
