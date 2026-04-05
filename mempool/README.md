# Protocol Guardian v2 — Mempool Pre-Transaction Detection

> Autonomous AI DeFi Security Agent that catches exploits **before** they land on-chain.

## The Problem

DeFi exploits caused **$3.7 billion in losses** between 2020-2025. Flash loan attacks alone account for **83% of all exploits**. Current security tools react to on-chain events *after* the damage is done. By the time a transaction is confirmed, the funds are gone.

## The Solution

Protocol Guardian v2 monitors the Ethereum **mempool** (pending transaction pool) and uses AI-powered threat analysis to detect exploits **before block confirmation**. The pipeline:

```
Mempool → Decode calldata → Match 32+ exploit signatures → Multi-vector scoring
→ Claude AI risk assessment → Autonomous pause() / Alert
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Ethereum Mempool                      │
│              (pending transactions)                      │
└──────────────────────┬──────────────────────────────────┘
                       │ WebSocket subscription
                       ▼
┌─────────────────────────────────────────────────────────┐
│              MempoolMonitor (monitor.py)                 │
│  • Alchemy enhanced API (filtered by watchlist)         │
│  • Standard newPendingTransactions (fallback)           │
│  • HTTP polling (secondary fallback)                    │
└──────────────────────┬──────────────────────────────────┘
                       │ raw transaction data
                       ▼
┌─────────────────────────────────────────────────────────┐
│           TransactionDecoder (decoder.py)                │
│  • Decode calldata, value, gas, nonce                   │
│  • Extract function selectors                           │
│  • Compute behavioral features                          │
└──────────────────────┬──────────────────────────────────┘
                       │ DecodedTransaction
                       ▼
┌─────────────────────────────────────────────────────────┐
│            ThreatAnalyzer (decoder.py)                   │
│  Phase 1: Primary selector match (32 signatures)        │
│  Phase 2: Deep calldata scan (nested/embedded calls)    │
│  Phase 3: Behavioral heuristics (gas, value, address)   │
│  Phase 4: Multi-vector combo detection                  │
│  Phase 5: Watched contract amplification                │
└──────────────────────┬──────────────────────────────────┘
                       │ ThreatReport (score, indicators)
                       ▼
              ┌────────┴────────┐
              │                 │
         score < 0.6       score ≥ 0.6
              │                 │
         LOG/ALERT        ESCALATE TO CLAUDE
              │                 │
              │                 ▼
              │     ┌──────────────────────┐
              │     │  Claude Risk Scorer  │
              │     │  (structured context │
              │     │   + exploit history) │
              │     └──────────┬───────────┘
              │                │
              │         score ≥ 0.8?
              │        ┌───────┴───────┐
              │        │               │
              │       YES             NO
              │        │               │
              │   PAUSE_CONTRACT   ALERT_TEAM
              └────────┴───────────────┘
```

## Exploit Signature Database

32 function selectors covering 6 attack categories, sourced from **400+ historical DeFi exploits**:

| Category | Signatures | Notable Exploits Referenced |
|----------|-----------|---------------------------|
| Flash Loan | 6 | Euler ($197M), Cream ($130M), Harvest ($34M) |
| Reentrancy | 6 | The DAO ($60M), Hundred Finance ($7M) |
| Oracle Manipulation | 5 | Bonq DAO ($120M), Warp Finance ($7.7M) |
| Access Control | 6 | Poly Network ($611M), Wormhole ($326M), Nomad ($190M) |
| Price Manipulation | 5 | PancakeBunny ($45M), Sandwich attacks |
| Governance | 4 | Beanstalk ($182M) |

### Multi-Vector Combo Detection

The analyzer detects dangerous combinations that amplify risk:
- **Flash Loan + Oracle Manipulation** → Classic DeFi exploit (Harvest-style)
- **Flash Loan + Reentrancy** → Amplified drain (Lendf.me-style)
- **Flash Loan + Price Manipulation** → DEX sandwich (PancakeBunny-style)
- **Access Control + Governance** → Protocol takeover (Beanstalk-style)

## Quick Start

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run in simulation mode (no Ethereum node needed)
python3 main_v2.py --simulate

# Run with live Sepolia mempool
python3 main_v2.py --ws-url wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY

# Run with Claude AI risk scoring
ANTHROPIC_API_KEY=sk-ant-... python3 main_v2.py --ws-url wss://...

# Run tests
python3 -m tests.test_mempool
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mempool/status` | GET | Monitor health, stats, recent threats |
| `/mempool/threats/stream` | GET | SSE real-time threat feed |
| `/mempool/threats` | GET | Recent threat history |
| `/mempool/watchlist` | GET/POST | Manage watched contracts |
| `/mempool/stats` | GET | Runtime statistics |
| `/health` | GET | Health check |
| `/docs` | GET | Interactive API docs (Swagger) |

## Test Results

```
Scenario                          Score   Level      Indicators
──────────────────────────────────────────────────────────────
Euler-style Flash Loan Exploit  100.0%  critical      5   ✅
Classic Reentrancy Drain         65.0%  high          1   ✅
Oracle Price Manipulation       100.0%  critical      6   ✅
Unauthorized Proxy Upgrade      100.0%  critical      2   ✅
Governance Takeover             100.0%  critical      4   ✅
Normal DEX Swap (benign)         50.0%  medium        1   ✅
Attack Contract Deployment       69.0%  high          2   ✅

Average analysis latency: 0.10 ms
```

## Contracts (Sepolia Testnet)

- **MockLendingPool**: `0x84568d45c653844BAe9d459311dD3487FcA2630E`
- **ProtocolGuardian**: `0x2344B12ae58c9c097C8400edbB1f9fB4DfCA12fE`

## Dashboard

Live at [protocol-guardian.vercel.app](https://protocol-guardian.vercel.app)

## License

MIT — Built for ETHGlobal Open Agents 2026
