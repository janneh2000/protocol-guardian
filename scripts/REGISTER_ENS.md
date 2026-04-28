# Registering the Guardian agent's ENS name on Sepolia

The dashboard's ENS layer (`dashboard/ens.js`) does the resolution at render
time — once an ENS name is set, the dashboard footer and watchlist start
showing human-readable names automatically. This guide registers the name.

## What you need

1. A Sepolia RPC URL (Alchemy / Infura / public).
2. A funded Sepolia wallet — the wallet whose address you want to brand
   as the Guardian. Roughly **0.01 Sepolia ETH** covers registration
   plus text records.
3. An unused name. Any label is fine. Recommend `protocol-guardian` so
   the agent surfaces as `protocol-guardian.eth`.

## .env values to add

Append to `/Users/rivaldo/Desktop/protocol-guardian/.env`:

```env
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-key>
GUARDIAN_AGENT_KEY=0xYOUR_PRIVATE_KEY_THAT_OWNS_THE_AGENT_ADDRESS
GUARDIAN_ENS_NAME=protocol-guardian
GUARDIAN_ENS_DESC=Autonomous DeFi security agent — pauses vulnerable contracts in real time.
GUARDIAN_ENS_GITHUB=janneh2000
GUARDIAN_ENS_URL=https://protocol-guardian.vercel.app
```

> The private key never leaves your laptop. The script signs locally with
> viem and broadcasts the resulting transaction — your key isn't pasted
> into any web UI or copied into the repo.

## One-shot path (recommended)

```bash
cd "/Users/rivaldo/Desktop/protocol-guardian"
node scripts/register_ens.mjs check    # confirm availability + price
node scripts/register_ens.mjs full     # commit, wait 65s, register, set records
```

`full` runs everything end-to-end. It takes ~2 minutes total because of the
ENS commit/reveal delay. When it finishes you'll see:

```
✓ protocol-guardian.eth now points at 0x2344B12ae58c9c097C8400edbB1f9fB4DfCA12fE.
✓ Text records set on protocol-guardian.eth
```

## Step-by-step alternative

If you want to inspect each step (or if `full` errors out somewhere mid-flow):

```bash
node scripts/register_ens.mjs check       # 1. price + availability
node scripts/register_ens.mjs commit      # 2. submit commitment
# wait 60+ seconds
node scripts/register_ens.mjs register    # 3. claim the name
node scripts/register_ens.mjs records     # 4. set description / url / github
```

The script saves the commit-secret to `.ens-secret.json` (gitignored)
so step 3 can recover the secret if your terminal session ends between
steps 2 and 3.

## What the dashboard does next

Once the name resolves, every place where the agent's address appears in
the dashboard footer auto-upgrades to `protocol-guardian.eth` on the next
page load — no extra config, the resolver in `dashboard/ens.js` reads
your address from `window.GUARDIAN_AGENT_ADDRESS` and hits Sepolia ENS
directly.

## Verifying

```bash
# Quick on-chain check from your Mac:
node -e "
import('viem').then(async (V) => {
  const { createPublicClient, http } = V;
  const { sepolia } = await import('viem/chains');
  const client = createPublicClient({ chain: sepolia, transport: http() });
  const name = await client.getEnsName({ address: '0x2344B12ae58c9c097C8400edbB1f9fB4DfCA12fE' });
  console.log('Reverse-resolved:', name);
});
"
```

If it prints `Reverse-resolved: protocol-guardian.eth`, everything is wired.

## If something goes wrong

- **"insufficient funds"** — top up the wallet with Sepolia ETH from
  `sepoliafaucet.com` and rerun.
- **"Need to wait Ns more after commit"** — the script's reveal window
  hasn't elapsed yet. Run `register` again after the printed wait.
- **"Name not available"** — somebody else owns it. Pick another label
  via `GUARDIAN_ENS_NAME` and rerun.
- **Resolver complains about wrong address** — the Sepolia ENS contract
  set is occasionally redeployed; the four constants at the top of
  `register_ens.mjs` (REGISTRAR, REGISTRY, PUBLIC_RESOLVER) may need a
  refresh from <https://docs.ens.domains/learn/deployments>.
