#!/usr/bin/env node
/**
 * Protocol Guardian — KeeperHub paid-intel bridge.
 *
 * When the AI agent lands in the ALERT confidence band (40-74) it needs
 * deeper threat intelligence than free public sources can offer. Premium
 * threat-intel feeds (Forta, OpenZeppelin Defender Sentinel, Chainalysis
 * Reactor, etc.) gate their best signals behind HTTP 402 paywalls using the
 * x402 (Base USDC) or MPP (Tempo USDC.e) protocols.
 *
 * KeeperHub's `@keeperhub/wallet` paymentSigner auto-pays those 402
 * challenges with a server-side Turnkey-custodied wallet, gated by a
 * three-tier PreToolUse safety hook (auto / ask / block) so a runaway
 * agent can't drain the wallet on inference. We call paymentSigner.fetch()
 * once per ALERT-band classification; the response either confirms the
 * threat (bump confidence into PAUSE) or refutes it (drop to IGNORE).
 *
 * Usage (called from agent/keeperhub_bridge.py via subprocess):
 *   node agent/keeperhub_intel.mjs <function-selector> <target-address>
 *
 * Stdout is a single JSON line: {"ok": true, "data": {...}}
 *                            or {"ok": false, "error": "..."}
 */

import { paymentSigner } from "@keeperhub/wallet";

const DEFAULT_INTEL_URL =
  process.env.GUARDIAN_INTEL_URL ||
  "https://api.keeperhub.com/api/mcp/workflows/threat-intel/call"; // x402-paid

async function lookup(signature, target) {
  const body = JSON.stringify({
    function_selector: signature,
    target_address: target,
    source: "protocol-guardian",
  });

  // paymentSigner.fetch() does the initial fetch; on 402 it pays the x402
  // (or MPP) challenge with our wallet's USDC and re-issues the request,
  // forwarding the original body + headers through the retry. Any non-402
  // response is returned untouched. The PreToolUse safety hook sits in
  // front of the actual signing call — small payments auto-approve, larger
  // ones surface for review, anything past the block ceiling is rejected.
  const response = await paymentSigner.fetch(DEFAULT_INTEL_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });

  if (!response.ok) {
    return { ok: false, status: response.status, body: await response.text() };
  }

  const data = await response.json();
  return { ok: true, data };
}

async function main() {
  const [, , signatureHex, targetAddress] = process.argv;
  if (!signatureHex || !targetAddress) {
    process.stderr.write(
      "usage: node keeperhub_intel.mjs <function-selector> <target-address>\n"
    );
    process.exit(2);
  }
  try {
    const result = await lookup(signatureHex, targetAddress);
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (err) {
    process.stdout.write(
      JSON.stringify({ ok: false, error: String(err && err.message ? err.message : err) }) + "\n"
    );
  }
}

main();
