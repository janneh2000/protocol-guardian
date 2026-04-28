"""
keeperhub_bridge.py — Python <-> Node bridge for KeeperHub agentic wallet.

The Protocol Guardian agent runtime is Python. KeeperHub's `@keeperhub/wallet`
paymentSigner is a Node ESM package. Rather than rewrite either side, we
subprocess into a small Node entrypoint (agent/keeperhub_intel.mjs) that
imports the SDK and performs the paid fetch.

Why we need it: when Claude classifies a transaction in the ALERT confidence
band (40-74), we want to consult premium threat-intel feeds before deciding
to pause or ignore. Those feeds gate behind x402 (Base USDC) or MPP (Tempo
USDC.e) paywalls. KeeperHub's paymentSigner auto-pays the 402 challenge with
a Turnkey-custodied wallet, gated by a PreToolUse safety hook (auto/ask/block).

The bridge is called from agent/ai_agent.py inside `analyse()` exactly once
per ALERT-band classification. Failure of the bridge never crashes the agent
— we degrade gracefully back to the un-enriched Claude decision.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("guardian.keeperhub")

_NODE_SCRIPT = Path(__file__).parent / "keeperhub_intel.mjs"
_DEFAULT_TIMEOUT_S = float(os.getenv("KEEPERHUB_TIMEOUT_S", "10"))


async def fetch_paid_intel(
    function_selector: str,
    target_address: str,
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Call the Node-side KeeperHub bridge. Returns parsed JSON or an error dict.

    Always returns a dict; never raises. The agent's analyse() path treats any
    {"ok": False, ...} response as "no enrichment available, keep Claude's
    original decision".
    """
    if not _NODE_SCRIPT.exists():
        return {"ok": False, "error": f"node script missing at {_NODE_SCRIPT}"}

    try:
        proc = await asyncio.create_subprocess_exec(
            "node",
            str(_NODE_SCRIPT),
            function_selector,
            target_address,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(_NODE_SCRIPT.parent.parent),  # repo root, so node_modules resolves
        )
    except FileNotFoundError:
        return {"ok": False, "error": "node binary not on PATH"}

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        return {"ok": False, "error": f"timeout after {timeout}s"}

    stdout = stdout_b.decode().strip()
    stderr = stderr_b.decode().strip()

    if not stdout:
        return {"ok": False, "error": stderr or "no stdout from keeperhub_intel.mjs"}

    # The script prints exactly one JSON line on stdout.
    try:
        return json.loads(stdout.splitlines()[-1])
    except json.JSONDecodeError as e:
        logger.warning(
            "keeperhub bridge produced non-JSON stdout: %s (stderr=%s)", stdout, stderr
        )
        return {"ok": False, "error": f"bad JSON from bridge: {e}"}


def reconcile_with_intel(decision_dict: dict, intel: dict) -> dict:
    """Merge Claude's initial decision with KeeperHub-paid intel.

    Heuristic: if upstream feed reports a confirmed exploit signature for the
    same selector, bump confidence into the PAUSE band. If upstream reports
    benign / known-safe pattern, drop to IGNORE. If upstream is silent, leave
    the decision untouched.
    """
    if not intel.get("ok"):
        return decision_dict

    data = intel.get("data") or {}
    verdict = (data.get("verdict") or "").lower()

    if verdict in ("confirmed_exploit", "high_risk"):
        decision_dict["confidence"] = max(int(decision_dict.get("confidence", 0)), 80)
        decision_dict["action"] = "PAUSE"
        decision_dict["rationale"] = (
            decision_dict.get("rationale", "") +
            " [Enriched by KeeperHub-paid threat-intel: " + verdict + "]"
        ).strip()
    elif verdict in ("benign", "known_safe", "whitelisted"):
        decision_dict["confidence"] = min(int(decision_dict.get("confidence", 100)), 30)
        decision_dict["action"] = "IGNORE"
        decision_dict["rationale"] = (
            decision_dict.get("rationale", "") +
            " [Refuted by KeeperHub-paid threat-intel: " + verdict + "]"
        ).strip()

    return decision_dict
