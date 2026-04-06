#!/bin/bash
# ═══════════════════════════════════════════════════════
#  Protocol Guardian v2 — Setup Script
#  Run from your protocol-guardian repo root:
#    chmod +x setup_v2.sh && ./setup_v2.sh
# ═══════════════════════════════════════════════════════

set -e
echo "╔══════════════════════════════════════════════════╗"
echo "║  Protocol Guardian v2 — Setup                    ║"
echo "╚══════════════════════════════════════════════════╝"

# ── 1. Create knowledge/ folder ──
echo "→ Creating knowledge/ folder..."
mkdir -p knowledge
touch knowledge/__init__.py

# ── 2. Create mempool/__init__.py if missing ──
echo "→ Checking mempool/__init__.py..."
if [ ! -f mempool/__init__.py ]; then
cat > mempool/__init__.py << 'PYEOF'
from .monitor import MempoolMonitor, MempoolConfig, MonitorStats, create_monitor
from .decoder import TransactionDecoder, ThreatAnalyzer, ThreatReport, DecodedTransaction
from .patterns import AttackCategory, ExploitSignature, SELECTOR_INDEX, ALL_SIGNATURES

__all__ = [
    "MempoolMonitor", "MempoolConfig", "MonitorStats", "create_monitor",
    "TransactionDecoder", "ThreatAnalyzer", "ThreatReport", "DecodedTransaction",
    "AttackCategory", "ExploitSignature", "SELECTOR_INDEX", "ALL_SIGNATURES",
]
PYEOF
echo "  Created mempool/__init__.py"
fi

# ── 3. Add new deps to requirements.txt if not present ──
echo "→ Checking dependencies..."
for dep in websockets aiohttp httpx; do
    if ! grep -q "$dep" requirements.txt 2>/dev/null; then
        echo "$dep" >> requirements.txt
        echo "  Added $dep to requirements.txt"
    fi
done

# ── 4. Install new deps ──
echo "→ Installing dependencies..."
pip3 install websockets aiohttp httpx --break-system-packages 2>/dev/null || \
pip3 install websockets aiohttp httpx 2>/dev/null || \
echo "  ⚠ pip install failed — install manually: pip3 install websockets aiohttp httpx"

# ── 5. Remind about files to copy ──
echo ""
echo "═══════════════════════════════════════════════════"
echo "  MANUAL STEPS:"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  1. Copy the downloaded main.py → replace your current main.py"
echo "  2. Copy the downloaded knowledge/exploit_db.py → knowledge/exploit_db.py"
echo "  3. Copy the downloaded protocol-guardian-dashboard.jsx → dashboard/"
echo ""
echo "  Then verify the mempool/ folder has these files:"
echo "    mempool/__init__.py"
echo "    mempool/api.py"
echo "    mempool/decoder.py"
echo "    mempool/monitor.py"
echo "    mempool/patterns.py"
echo ""
echo "  Remove main_v2.py from mempool/ if it's still there:"
echo "    rm -f mempool/main_v2.py"
echo ""
echo "═══════════════════════════════════════════════════"
echo "  GIT COMMANDS:"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  git add -A"
echo '  git commit -m "feat: Protocol Guardian v2 — mempool pre-tx detection + RAG exploit knowledge base + dashboard upgrade"'
echo "  git push origin main"
echo ""
echo "═══════════════════════════════════════════════════"
echo "  TEST:"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  python3 -m mempool.patterns     # Verify 32 signatures load"
echo "  python3 -m knowledge.exploit_db  # Verify 21 exploits / \$3.7B"
echo "  python3 main.py --simulate --no-ai  # Full agent test"
echo ""
echo "✅ Setup complete!"
