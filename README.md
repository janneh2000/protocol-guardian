# Protocol Guardian Agent

> Autonomous AI sentinel for DeFi protocol security. Monitors the Ethereum mempool in real-time, classifies threats using Claude AI, and autonomously calls `pause()` on vulnerable contracts before exploits complete.

Built for **ETHGlobal Open Agents 2026**.

---

## What it does

| Layer | What happens |
|---|---|
| **Ingestion** | Subscribes to Ethereum mempool + blocks via Alchemy WebSocket |
| **Heuristics** | Fast pattern screening: flash loans, oracle deviations, TVL drains |
| **AI Reasoning** | Claude classifies the attack type, scores confidence 0–100, decides action |
| **Action** | Calls `emergencyPause()` on the Guardian contract if confidence ≥ 75% |
| **Report** | Claude generates a full post-incident security report |
| **Dashboard** | Live HTML dashboard showing events, confidence scores, and reports |

---

## Architecture

```
Ethereum Mempool / Blocks
         │
         ▼
 BlockchainIngestion       ← web3.py WebSocket subscription
         │
         ▼
  HeuristicsEngine         ← flash loan, oracle, drain pattern checks
         │  (risk_score ≥ 30 → escalate)
         ▼
      AIAgent              ← Claude: classify + confidence + action
         │
    ┌────┴────┐
    │         │
  PAUSE     ALERT
    │
    ▼
GuardianController.sol     ← onchain: calls protocol.pause()
    │
    ▼
  ReportGenerator          ← Claude: post-incident markdown report
```

---

## Prerequisites

- Python 3.11+
- Node.js 18+
- Git
- A funded Sepolia wallet (0.1 ETH minimum — get from [sepoliafaucet.com](https://sepoliafaucet.com/))
- Alchemy account (free) — [dashboard.alchemy.com](https://dashboard.alchemy.com)
- Anthropic API key — [console.anthropic.com](https://console.anthropic.com)

---

## Step-by-step setup

### Step 1 — Clone the repo

```bash
git clone https://github.com/janneh2000/protocol-guardian.git
cd protocol-guardian
```

### Step 2 — Install Node dependencies

```bash
npm install
```

This installs Hardhat, OpenZeppelin contracts, and the deploy tooling.

### Step 3 — Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Step 4 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in every value:

```env
# Alchemy — create an app at dashboard.alchemy.com, select Sepolia
ALCHEMY_WS_RPC=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ALCHEMY_HTTP_RPC=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY

# Anthropic
ANTHROPIC_API_KEY=sk-ant-...

# Your Sepolia wallet private key (needs 0.1 ETH)
DEPLOYER_PRIVATE_KEY=0x...

# For the hackathon, use the same key for the guardian hot wallet
GUARDIAN_HOT_WALLET_PRIVATE_KEY=0x...

# Run this to get the address from your key:
# python scripts/get_address.py 0xYOUR_PRIVATE_KEY
GUARDIAN_HOT_WALLET=0x...

# Same key for attack simulator
ATTACKER_PRIVATE_KEY=0x...

# Leave these blank for now — filled after Step 5
LENDING_POOL_ADDRESS=
GUARDIAN_CONTRACT_ADDRESS=
```

> **Security note**: Never commit `.env`. It is in `.gitignore`.

### Step 5 — Compile and deploy contracts

```bash
# Compile Solidity
npx hardhat compile

# Deploy to Sepolia
npx hardhat run scripts/deploy.js --network sepolia
```

Expected output:
```
Deploying with account: 0xYourAddress
Account balance: 0.5 ETH

[1/3] Deploying MockLendingPool...
MockLendingPool deployed to: 0xAAA...

[2/3] Seeding pool with 0.1 ETH liquidity...
Pool seeded. Total liquidity: 0.1 ETH

[3/3] Deploying ProtocolGuardian...
ProtocolGuardian deployed to: 0xBBB...

[4/4] Granting PAUSER_ROLE to ProtocolGuardian...
PAUSER_ROLE granted.

✅ Deployment complete!
MockLendingPool:  0xAAA...
ProtocolGuardian: 0xBBB...
```

**Copy the two addresses into your `.env`:**

```env
LENDING_POOL_ADDRESS=0xAAA...
GUARDIAN_CONTRACT_ADDRESS=0xBBB...
```

### Step 6 — Start the guardian agent

Open **Terminal 1**:

```bash
source venv/bin/activate
python main.py
```

You should see:
```
╔══════════════════════════════════════════════════╗
║     Protocol Guardian Agent — Starting Up        ║
╠══════════════════════════════════════════════════╣
║  Ingestion  → WebSocket mempool + block stream   ║
║  Heuristics → Flash loan, drain, oracle checks   ║
║  AI Layer   → Claude threat classification       ║
║  Action     → Onchain emergencyPause()           ║
║  Reports    → Auto-generated incident reports    ║
╚══════════════════════════════════════════════════╝

INFO guardian.main — Monitoring pool: 0xAAA...
INFO guardian.ingestion — Connected to Ethereum node via WebSocket
INFO guardian.ingestion — Subscribed to pending transactions (mempool)
INFO guardian.ingestion — Subscribed to new blocks
```

### Step 7 — Open the dashboard

In a browser, open:
```
dashboard/index.html
```

Or serve it locally:
```bash
cd dashboard && python3 -m http.server 8080
# Open: http://localhost:8080
```

### Step 8 — Run the attack simulator (DEMO)

Open **Terminal 2**:

```bash
source venv/bin/activate
python scripts/attack_simulator.py
```

Watch **Terminal 1** (guardian) respond in real time:

```
INFO  guardian.ingestion — Interesting pending tx: 0xabc123... | flash_loan=True
INFO  guardian.heuristics — Heuristics [0xabc123]: Detected signals: oracle_price_manipulation, flash_loan_detected. Risk: 65/100
INFO  guardian.ai_agent — Invoking Claude for tx: 0xabc123...
INFO  guardian.ai_agent — Decision: PAUSE | flash_loan_price_manipulation | confidence=91%
CRITICAL guardian.action — PAUSING PROTOCOL — flash_loan_price_manipulation | confidence=91%
CRITICAL guardian.action — Pause tx submitted: 0xdef456...
CRITICAL guardian.action — PROTOCOL PAUSED SUCCESSFULLY. Block: 7234567

POST-INCIDENT REPORT
════════════════════
Title:     Flash Loan Oracle Manipulation — MockLendingPool
Severity:  Critical
Summary:   Attacker exploited oracle price feed to inflate borrow capacity...
Protected: $42,000
```

In Terminal 2:
```
[ATTACKER] Borrow FAILED: Protocol is PAUSED!
[GUARDIAN] Attack neutralised successfully.
```

---

## Simulate mode (no real transactions)

To test without spending gas:

```bash
python main.py --simulate
```

The agent runs the full pipeline (ingestion → heuristics → AI → decision) but skips the onchain `pause()` call. Use this to verify everything is wired correctly before funding the hot wallet.

---

## Project structure

```
protocol-guardian/
├── contracts/
│   ├── MockLendingPool.sol      # Protocol being monitored (demo target)
│   └── ProtocolGuardian.sol     # Guardian controller (holds PAUSER_ROLE)
├── scripts/
│   ├── deploy.js                # Hardhat deployment script
│   ├── attack_simulator.py      # Demo attack: oracle manipulation + drain
│   └── get_address.py           # Derive address from private key
├── agent/
│   ├── main.py                  # Entry point, orchestrator
│   ├── ingestion.py             # WebSocket mempool + block subscription
│   ├── heuristics.py            # Fast pattern screening
│   ├── ai_agent.py              # Claude reasoning layer
│   ├── exploit_rag.py           # Historical exploit database (RAG)
│   ├── action.py                # Onchain execution + alerts
│   └── report.py                # Post-incident report generator
├── dashboard/
│   └── index.html               # Live event dashboard
├── abi/                         # Auto-generated after compile
├── .env.example                 # Environment variable template
├── requirements.txt             # Python dependencies
├── package.json                 # Node/Hardhat dependencies
└── hardhat.config.js            # Hardhat configuration
```

---

## How the AI reasoning works

The AI layer receives a structured prompt containing:

1. **Transaction data** — hash, from/to, value, input selector
2. **Pool state** — liquidity before/after, oracle price before/after
3. **Heuristics signals** — pre-screened risk factors with severity scores
4. **RAG context** — 3 most similar historical exploits from DeFiHackLabs database

Claude returns structured JSON:

```json
{
  "attack_type": "flash_loan_price_manipulation",
  "confidence": 91,
  "action": "PAUSE",
  "suspected_attacker": "0xAttackerAddress",
  "estimated_loss_usd": 42000,
  "rationale": "Transaction exhibits classic flash loan oracle manipulation pattern. Attacker borrowed large ETH position, immediately updated oracle price by 50%, then attempted to borrow against artificially deflated collateral. Pattern matches Mango Markets exploit (Oct 2022, $116M). Pool balance at immediate risk."
}
```

Action thresholds:
- **PAUSE** → confidence ≥ 75%
- **ALERT** → confidence 40–74%
- **IGNORE** → confidence < 40%

The confidence threshold is also enforced **onchain** in `ProtocolGuardian.sol` — a compromised guardian key cannot pause with confidence < 75.

---

## What makes this different from Forta + OZ Defender

| Feature | Forta + Defender | Protocol Guardian |
|---|---|---|
| Detection method | Hardcoded rules | AI reasoning with context |
| Novel attack vectors | Misses them | Can reason about new patterns |
| Rationale | None | Plain-English explanation |
| Post-incident report | Manual | Auto-generated by Claude |
| RAG on past exploits | No | Yes — DeFiHackLabs dataset |
| Confidence scoring | Binary | 0–100 with threshold enforcement |

---

## Sepolia testnet links

- Sepolia Etherscan: [sepolia.etherscan.io](https://sepolia.etherscan.io)
- Sepolia faucet: [sepoliafaucet.com](https://sepoliafaucet.com)
- Alchemy dashboard: [dashboard.alchemy.com](https://dashboard.alchemy.com)

---

## Built with

- [Anthropic Claude](https://anthropic.com) — AI threat reasoning
- [web3.py](https://web3py.readthedocs.io) — Ethereum interaction
- [Hardhat](https://hardhat.org) — Contract compilation and deployment
- [OpenZeppelin](https://openzeppelin.com) — Pausable + AccessControl base contracts
- [Alchemy](https://alchemy.com) — WebSocket mempool subscriptions
- [DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) — Historical exploit dataset

---

## License

MIT
