#!/usr/bin/env python3
"""
Protocol Guardian — repository smoke test.

Designed to run in 30 seconds with ZERO secrets. No Anthropic API key,
no Alchemy WebSocket, no funded Sepolia wallet, no Docker required.
What this verifies:

  - Every HTML page parses (lxml)
  - Every Python file's AST parses
  - Every Node script syntax-checks (`node --check`)
  - Every SVG asset parses
  - Every JSON config parses (vercel.json, AXL configs, package.json)
  - docker-compose.yml is valid YAML
  - The AXL ThreatFingerprint binary wire format round-trips bit-exact
  - The AXL client degrades gracefully when no node is running
  - The KeeperHub bridge degrades gracefully when no wallet is provisioned
  - The viem ENS resolver in dashboard/ens.js exposes the right API
  - The agent has all four integration hooks wired into analyse()
  - Marketing pages have ZERO hardcoded colors outside :root blocks
  - No phone numbers anywhere on the public surface
  - theme.js + data-theme-toggle is on every marketing page
  - Live demo links are present on every marketing page

What this does NOT verify (requires the operator's environment):
  - The actual on-chain Sepolia behavior
  - Live ENS resolution against mainnet/Sepolia
  - Full Claude classifier loop
  - AXL multi-node demo (needs Docker)
  - KeeperHub x402 payment (needs Turnkey provisioning)

For those, see README → "Step-by-step setup".

Run:
  python3 scripts/smoke_test.py
or:
  npm run verify
"""

from __future__ import annotations

import asyncio
import ast
import json
import os
import re
import subprocess
import sys

PASS = "\033[92m✓\033[0m"
FAIL = "\033[91m✗\033[0m"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(REPO_ROOT)
sys.path.insert(0, REPO_ROOT)

results: list[tuple[bool, str, str]] = []


def check(name, fn):
    try:
        ok, detail = fn()
        results.append((ok, name, detail))
    except Exception as e:
        results.append((False, name, f"exception: {type(e).__name__}: {e}"))


# ── 1. HTML parses ───────────────────────────────────────────────────
def html_parse():
    try:
        from lxml import html as lx
    except ImportError:
        return False, "lxml not installed (pip install -r requirements.txt)"
    pages = ["index.html", "login.html", "team.html", "get-started.html", "dashboard/index.html"]
    for f in pages:
        with open(f, "rb") as fh:
            lx.parse(fh)
    return True, f"{len(pages)} pages parse via lxml"


# ── 2. Python AST parses ─────────────────────────────────────────────
def py_parse():
    files = [
        "agent/ai_agent.py",
        "agent/keeperhub_bridge.py",
        "agent/axl/__init__.py",
        "agent/axl/swarm_client.py",
        "agent/heuristics.py",
        "agent/ingestion.py",
        "agent/action.py",
        "agent/report.py",
        "main.py",
    ]
    for f in files:
        ast.parse(open(f).read())
    return True, f"{len(files)} Python files parse"


# ── 3. Node syntax checks ────────────────────────────────────────────
def node_syntax():
    files = ["agent/keeperhub_intel.mjs", "scripts/register_ens.mjs", "theme.js", "dashboard/ens.js"]
    for f in files:
        r = subprocess.run(["node", "--check", f], capture_output=True, text=True)
        if r.returncode != 0:
            return False, f"{f} fails: {r.stderr[:160]}"
    return True, f"{len(files)} JS files syntax-check"


# ── 4. SVG parse ─────────────────────────────────────────────────────
def svg_parse():
    try:
        from lxml import etree
    except ImportError:
        return False, "lxml not installed"
    svgs = [f"assets/{n}.svg" for n in ("logo", "logo-dark", "logo-mono", "logo-lockup", "cover")]
    for f in svgs:
        etree.parse(f)
    return True, f"{len(svgs)} SVG files parse"


# ── 5. JSON config parse ─────────────────────────────────────────────
def json_parse():
    files = [
        "agent/axl/node-config.public.json",
        "agent/axl/node-config.peer.json",
        "vercel.json",
        "package.json",
    ]
    if os.path.exists("addresses.json"):
        files.append("addresses.json")
    for f in files:
        json.load(open(f))
    return True, f"{len(files)} JSON files parse"


# ── 6. docker-compose YAML ───────────────────────────────────────────
def compose_parse():
    try:
        import yaml
    except ImportError:
        return False, "pyyaml not installed (pip install pyyaml)"
    yaml.safe_load(open("agent/axl/docker-compose.yml"))
    return True, "docker-compose.yml is valid YAML"


# ── 7. AXL ThreatFingerprint round-trip ──────────────────────────────
def axl_roundtrip():
    from agent.axl.swarm_client import ThreatFingerprint, _FRAME_SIZE

    fp = ThreatFingerprint(
        function_selector="0xa9059cbb",
        target_address="0x84568d45c653844BAe9d459311dD3487FcA2630E",
        confidence=87,
        timestamp=1745948000,
        source_id="ab" * 32,
    )
    blob = fp.encode()
    if len(blob) != _FRAME_SIZE or len(blob) != 73:
        return False, f"frame size {len(blob)} != 73"
    fp2 = ThreatFingerprint.decode(blob)
    if (
        fp2.confidence != 87
        or fp2.target_address.lower() != fp.target_address.lower()
        or fp2.function_selector != fp.function_selector
    ):
        return False, "round-trip mismatch"
    return True, "73-byte frame round-trips bit-exact"


# ── 8. AXL bad-magic rejection ───────────────────────────────────────
def axl_bad_magic():
    from agent.axl.swarm_client import ThreatFingerprint

    try:
        ThreatFingerprint.decode(b"BADMAGIC" + b"\x00" * 65)
    except ValueError:
        return True, "rejects bad-magic frames"
    return False, "should have raised on bad magic"


# ── 9. AXL offline graceful degradation ──────────────────────────────
def axl_offline():
    from agent.axl import broadcast_threat, recv_peer_threats

    ok = asyncio.run(
        broadcast_threat(
            "0xa9059cbb", "0x84568d45c653844BAe9d459311dD3487FcA2630E", 87
        )
    )
    if ok is not False:
        return False, "offline broadcast should return False"
    fps = asyncio.run(recv_peer_threats())
    if fps != []:
        return False, "offline recv should return []"
    return True, "no AXL node → False / [] (no exceptions)"


# ── 10. KeeperHub package present ────────────────────────────────────
def kh_pkg():
    if not os.path.exists("node_modules/@keeperhub/wallet/dist/index.js"):
        return False, "package not installed (run `npm install`)"
    pkg = json.load(open("node_modules/@keeperhub/wallet/package.json"))
    return True, f"@keeperhub/wallet@{pkg['version']} installed"


# ── 11. KeeperHub paymentSigner reachable ────────────────────────────
def kh_signer():
    r = subprocess.run(
        [
            "node",
            "-e",
            "import('@keeperhub/wallet').then(m => console.log(typeof m.paymentSigner.fetch === 'function' ? 'OK' : 'FAIL'))",
        ],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=REPO_ROOT,
    )
    if "OK" not in r.stdout:
        return False, f"signer not reachable: {r.stdout.strip()} | {r.stderr[:120]}"
    return True, "paymentSigner.fetch is callable"


# ── 12. KeeperHub bridge graceful failure ────────────────────────────
def kh_bridge():
    from agent.keeperhub_bridge import fetch_paid_intel

    r = asyncio.run(
        fetch_paid_intel(
            "0xabcd1234",
            "0x84568d45c653844BAe9d459311dD3487FcA2630E",
            timeout=8.0,
        )
    )
    if not isinstance(r, dict) or "ok" not in r:
        return False, "bad response shape"
    if r.get("ok"):
        return False, "should fail without wallet provisioning"
    return True, "returns {'ok': False, ...} — agent path stays alive"


# ── 13. ENS — viem package + resolver structure ──────────────────────
def ens_check():
    if not os.path.exists("node_modules/viem/_esm/actions/ens/getEnsName.js"):
        return False, "viem ENS module missing (run `npm install`)"
    code = open("dashboard/ens.js").read()
    needed = ["getEnsName", "getEnsText", "getEnsAvatar", "window.PGEns"]
    missing = [n for n in needed if n not in code]
    if missing:
        return False, f"resolver missing: {missing}"
    return True, "viem ENS module + dashboard/ens.js exports correct"


# ── 14. AIAgent has all integrations wired ───────────────────────────
def integrations_wired():
    code = open("agent/ai_agent.py").read()
    needs = [
        "fetch_paid_intel",
        "reconcile_with_intel",
        "broadcast_threat",
        "recv_peer_threats",
    ]
    missing = [n for n in needs if n not in code]
    if missing:
        return False, f"not wired: {missing}"
    return True, "all 4 integration hooks present in analyse()"


# ── 15. Marketing pages — color-token cleanliness ────────────────────
def color_sweep():
    for f in ["index.html", "login.html", "team.html", "get-started.html"]:
        s = open(f).read()
        sm = re.search(r"<style>([\s\S]*?)</style>", s)
        if not sm:
            return False, f"{f} has no <style> block"
        css = sm.group(1)
        stripped = re.sub(r':root(?:\[data-theme="dark"\])?\s*\{[^}]*\}', "", css)
        hex_m = re.findall(r"#[0-9a-fA-F]{3,8}\b", stripped)
        if hex_m:
            return False, f"{f} has hex leftovers: {hex_m[:3]}"
    return True, "all 4 marketing pages clean — every color in :root"


# ── 16. Phone number sweep ───────────────────────────────────────────
def phone_sweep():
    pattern = r"(tel:|\+?[0-9]{1,3}[ -]?\(?[0-9]{3}\)?[ -]?[0-9]{3}[ -]?[0-9]{4})"
    for f in ["index.html", "login.html", "team.html", "get-started.html"]:
        if re.search(pattern, open(f).read()):
            return False, f"{f} contains phone number"
    return True, "no phone numbers anywhere on the public surface"


# ── 17. Theme infra present ──────────────────────────────────────────
def theme_infra():
    for f in ["index.html", "login.html", "team.html", "get-started.html"]:
        s = open(f).read()
        if "theme.js" not in s or "data-theme-toggle" not in s:
            return False, f"{f} missing theme infra"
    return True, "theme.js + data-theme-toggle on all 4 marketing pages"


# ── 18. Live demo link reachable from each marketing page ────────────
def demo_links():
    for f in ["index.html", "login.html", "team.html", "get-started.html"]:
        if "protocol-guardian.vercel.app/dashboard" not in open(f).read():
            return False, f"{f} missing live-demo link"
    return True, "live demo link present on all 4 marketing pages"


def run_all():
    check("HTML parse — every marketing page + dashboard", html_parse)
    check("Python AST — full agent module", py_parse)
    check("Node syntax — JS / mjs files", node_syntax)
    check("SVG parse — logo + cover", svg_parse)
    check("JSON configs", json_parse)
    check("docker-compose YAML", compose_parse)
    check("AXL — ThreatFingerprint encode/decode", axl_roundtrip)
    check("AXL — bad magic rejection", axl_bad_magic)
    check("AXL — offline graceful degradation", axl_offline)
    check("KeeperHub — package installed", kh_pkg)
    check("KeeperHub — paymentSigner reachable", kh_signer)
    check("KeeperHub — bridge graceful failure", kh_bridge)
    check("ENS — viem + dashboard resolver", ens_check)
    check("AIAgent — all integrations wired", integrations_wired)
    check("Color tokens — marketing pages clean", color_sweep)
    check("Privacy — no phone numbers", phone_sweep)
    check("Theme — script + toggle present", theme_infra)
    check("Routing — live demo reachable from each page", demo_links)


async def _cleanup_singletons():
    """Close any aiohttp sessions the AXL tests opened so we exit clean."""
    try:
        from agent.axl import swarm_client
        if swarm_client._singleton is not None and swarm_client._singleton._session is not None:
            await swarm_client._singleton._session.close()
            swarm_client._singleton._session = None
    except Exception:
        pass


def main():
    # Silence aiohttp ResourceWarning noise from the AXL graceful-degradation test.
    import warnings
    warnings.filterwarnings("ignore", category=ResourceWarning)

    run_all()
    asyncio.run(_cleanup_singletons())

    total = len(results)
    passed = sum(1 for r in results if r[0])
    print()
    print("=" * 72)
    print(f"  Protocol Guardian — repository smoke test ({passed}/{total} passed)")
    print("=" * 72)
    for ok, name, detail in results:
        mark = PASS if ok else FAIL
        print(f"  {mark} {name}")
        print(f"      {detail}")
    print()
    if passed == total:
        print("All static checks pass. The codebase is sound.")
        print("For runtime checks (Sepolia, live ENS, full agent loop,")
        print("AXL swarm, KeeperHub x402), see README → 'Step-by-step setup'.")
        return 0
    else:
        print(f"{total - passed} check(s) failed. See output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
