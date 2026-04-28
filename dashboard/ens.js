/**
 * Protocol Guardian — ENS resolution layer (browser-side).
 *
 * The dashboard renders raw 0x… addresses for the Guardian agent itself,
 * the on-chain GuardianController contract, and every monitored protocol
 * in the watchlist. Hex addresses are unreadable. This module turns them
 * into ENS names at render time using viem.
 *
 * Resolution strategy (functional, no hardcoded values — ENS prize req.):
 *   1. Try Sepolia ENS (where Protocol Guardian itself lives).
 *   2. Fall back to mainnet ENS for protocols whose canonical names live
 *      there (aave.eth, uniswap.eth, etc.).
 *   3. Cache hits in-memory; a refresh fetches fresh.
 *
 * Public API:
 *   - PGEns.resolveEnsName(address)   → Promise<{ name, network } | null>
 *   - PGEns.resolveEnsAvatar(name)    → Promise<string | null>
 *   - PGEns.resolveEnsText(name, key) → Promise<string | null>
 *   - PGEns.applyEnsToDom(root?)      → upgrades [data-ens-address]
 *                                       elements in-place.
 *   - PGEns.guardianIdentity()        → resolves the agent's own ENS,
 *                                       text records, and avatar in one
 *                                       call. Returns null if unset.
 *
 * Usage in dashboard markup:
 *   <span data-ens-address="0xAbc…">0xAbc…</span>
 *   On DOM ready, call PGEns.applyEnsToDom(); each matched element's
 *   text content is replaced with the resolved ENS name (when one
 *   exists), and a `data-ens-name` attribute is set so subsequent
 *   reads are O(1).
 */

import { createPublicClient, http, isAddress, getAddress } from "https://esm.sh/viem@2.21.45";
import { sepolia, mainnet } from "https://esm.sh/viem@2.21.45/chains";

// Public RPCs — fine for read-only ENS lookups.
const sepoliaClient = createPublicClient({ chain: sepolia, transport: http() });
const mainnetClient = createPublicClient({ chain: mainnet, transport: http() });

const _nameCache = new Map();   // address (checksummed) -> { name, network } | null
const _textCache = new Map();   // `${name}|${key}` -> value | null
const _avatarCache = new Map(); // name -> url | null

function _norm(address) {
  if (!address || typeof address !== "string") return null;
  if (!isAddress(address)) return null;
  return getAddress(address);
}

/** Reverse-resolve an address. Tries Sepolia first, then mainnet. */
async function resolveEnsName(address) {
  const checksummed = _norm(address);
  if (!checksummed) return null;
  if (_nameCache.has(checksummed)) return _nameCache.get(checksummed);

  let result = null;
  try {
    const name = await sepoliaClient.getEnsName({ address: checksummed });
    if (name) result = { name, network: "sepolia" };
  } catch (_) { /* swallow — fall through to mainnet */ }

  if (!result) {
    try {
      const name = await mainnetClient.getEnsName({ address: checksummed });
      if (name) result = { name, network: "mainnet" };
    } catch (_) { /* both failed — cache null */ }
  }

  _nameCache.set(checksummed, result);
  return result;
}

async function _clientFor(network) {
  return network === "sepolia" ? sepoliaClient : mainnetClient;
}

async function resolveEnsAvatar(name) {
  if (!name) return null;
  if (_avatarCache.has(name)) return _avatarCache.get(name);
  let avatar = null;
  for (const client of [sepoliaClient, mainnetClient]) {
    try {
      avatar = await client.getEnsAvatar({ name });
      if (avatar) break;
    } catch (_) { /* try next */ }
  }
  _avatarCache.set(name, avatar);
  return avatar;
}

async function resolveEnsText(name, key) {
  if (!name || !key) return null;
  const cacheKey = `${name}|${key}`;
  if (_textCache.has(cacheKey)) return _textCache.get(cacheKey);
  let value = null;
  for (const client of [sepoliaClient, mainnetClient]) {
    try {
      value = await client.getEnsText({ name, key });
      if (value) break;
    } catch (_) { /* try next */ }
  }
  _textCache.set(cacheKey, value);
  return value;
}

/**
 * Walk the DOM under `root` (default: document) and upgrade every
 * [data-ens-address] element's text content to the resolved ENS name
 * if one exists. Sets [data-ens-name] for downstream consumers.
 *
 * Original short-form fallback (e.g. "0x8456…630E") is preserved as a
 * tooltip via the title attribute so operators can still copy the raw hex.
 */
async function applyEnsToDom(root) {
  const scope = root || document;
  const nodes = scope.querySelectorAll("[data-ens-address]:not([data-ens-resolved])");
  const promises = [];
  nodes.forEach((node) => {
    const addr = node.getAttribute("data-ens-address");
    promises.push(
      resolveEnsName(addr).then((res) => {
        node.setAttribute("data-ens-resolved", "true");
        if (!res) return;
        const original = node.textContent;
        node.setAttribute("data-ens-name", res.name);
        node.setAttribute("title", original + " · resolved on " + res.network);
        node.textContent = res.name;
      }).catch(() => {})
    );
  });
  await Promise.all(promises);
}

/**
 * Resolve the agent's own identity bundle. The agent's address is read
 * from an addressable global (window.GUARDIAN_AGENT_ADDRESS, which the
 * dashboard sets from addresses.json). If unset or unresolvable, returns
 * null and the dashboard falls back to the raw address.
 */
async function guardianIdentity() {
  const addr = window.GUARDIAN_AGENT_ADDRESS;
  if (!addr) return null;
  const ens = await resolveEnsName(addr);
  if (!ens) return null;
  const [avatar, github, description, url, twitter] = await Promise.all([
    resolveEnsAvatar(ens.name),
    resolveEnsText(ens.name, "com.github"),
    resolveEnsText(ens.name, "description"),
    resolveEnsText(ens.name, "url"),
    resolveEnsText(ens.name, "com.twitter"),
  ]);
  return {
    address: addr,
    name: ens.name,
    network: ens.network,
    avatar,
    github,
    description,
    url,
    twitter,
  };
}

window.PGEns = {
  resolveEnsName,
  resolveEnsAvatar,
  resolveEnsText,
  applyEnsToDom,
  guardianIdentity,
};

// Auto-apply on DOM ready unless the dashboard opts out by setting
// window.PG_ENS_NO_AUTOAPPLY = true before this script loads.
if (!window.PG_ENS_NO_AUTOAPPLY) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      applyEnsToDom();
    });
  } else {
    applyEnsToDom();
  }
}

export {
  resolveEnsName,
  resolveEnsAvatar,
  resolveEnsText,
  applyEnsToDom,
  guardianIdentity,
};
