# Protocol Guardian × Gensyn AXL — swarm layer

Each Protocol Guardian instance runs its own AXL node ([gensyn-ai/axl](https://github.com/gensyn-ai/axl)).
When one Guardian classifies a transaction with high confidence it broadcasts a
**threat fingerprint** through its local AXL node's `/send` endpoint. Every peer
Guardian polls `/recv`, sees the incoming fingerprint, and raises its
confidence floor for any transaction matching the same selector + target —
all without a centralised broker.

## Wire format

73 bytes, fixed-size, network byte order:

| field        | bytes | notes                                         |
|--------------|-------|-----------------------------------------------|
| `magic`      | 8     | `b"PGTHRT01"`                                 |
| `selector`   | 4     | function selector (e.g. `0xa9059cbb`)         |
| `target`     | 20    | target contract address                       |
| `confidence` | 1     | 0..100                                        |
| `timestamp`  | 8     | unix epoch seconds                            |
| `source_id`  | 32    | broadcaster's AXL pubkey (zeros if unknown)   |

Encode/decode lives in `swarm_client.py::ThreatFingerprint`.

## Topology

```
   ┌──────────────┐         ┌──────────────┐
   │  Guardian A  │         │  Guardian B  │
   │  (Alice)     │         │  (Bob)       │
   │              │         │              │
   │  Python      │         │  Python      │
   │  agent       │         │  agent       │
   │  ──────►     │         │  ──────►     │
   │  /send :9090 │         │  /recv :9090 │
   │              │         │              │
   │  axl-node    │◄───────►│  axl-node    │
   └──────┬───────┘  TLS    └──────┬───────┘
          │                        │
          │     ┌──────────────┐   │
          └────►│ axl-public   │◄──┘
                │ (rendezvous) │
                │ tls://:9001  │
                └──────────────┘
```

## Running the demo

The repo ships a 3-node compose stack: one public rendezvous node, two
Guardian peers (Alice and Bob).

```bash
cd "/Users/rivaldo/Desktop/protocol-guardian"
docker compose -f agent/axl/docker-compose.yml up --build
```

That brings up:

- `axl-public`  — TLS listener on host `:9001`, HTTP bridge on host `:9090`
- `axl-alice`   — Guardian #1, HTTP bridge on host `:9091`
- `axl-bob`     — Guardian #2, HTTP bridge on host `:9092`

The first build pulls and compiles `gensyn-ai/axl` (Go 1.25.5). Subsequent
runs are cached and start in seconds.

## Smoke test from your Mac

In one terminal, point a Python session at Alice and broadcast a
fingerprint:

```bash
cd "/Users/rivaldo/Desktop/protocol-guardian"
AXL_BASE_URL=http://localhost:9091 python3 - <<'PY'
import asyncio, time
from agent.axl import broadcast_threat
asyncio.run(broadcast_threat(
    function_selector="0xa9059cbb",
    target_address="0x84568d45c653844BAe9d459311dD3487FcA2630E",
    confidence=87,
))
PY
```

In another terminal, point at Bob and pull:

```bash
AXL_BASE_URL=http://localhost:9092 python3 - <<'PY'
import asyncio
from agent.axl import recv_peer_threats
fps = asyncio.run(recv_peer_threats())
for fp in fps: print(fp)
PY
```

Bob should print Alice's fingerprint within a second or two — proving
inter-node communication via AXL with no centralised broker.

## Production wiring

The Python agent in `agent/ai_agent.py` calls `broadcast_threat()` after
any PAUSE-band decision and consults `recv_peer_threats()` at the start
of every classification. See the `# ── AXL swarm` comments there.

## Configuration

`node-config.public.json` — listening node. Run on a publicly reachable
host; this becomes the rendezvous for fresh networks.

`node-config.peer.json` — Guardian-attached peer. Set `Peers` to your
public node's `tls://host:9001` URL. The compose stack uses the
container DNS name `axl-public` for that.

Per-AXL-node env vars consumed by `swarm_client.py`:

| var            | default                  | meaning                                   |
|----------------|--------------------------|-------------------------------------------|
| `AXL_BASE_URL` | `http://localhost:9090`  | local HTTP bridge URL                     |
| `AXL_NODE_ID`  | `0..0` (32 bytes)        | hex source identifier in fingerprints     |
| `AXL_TOPIC`    | `pg-threats`             | logical topic on send/recv                |
