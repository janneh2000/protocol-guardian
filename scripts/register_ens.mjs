#!/usr/bin/env node
/**
 * scripts/register_ens.mjs — Register a .eth name on Sepolia and set
 * text records branding the address as the Protocol Guardian agent.
 *
 * Why a script: ENS registration is two transactions with a 60-second
 * commit/reveal window, plus several record-setting txs. Doing this by
 * hand in the ENS web UI works, but a script makes the demo reproducible
 * and gives us a single permalink to point the prize-form's "line of
 * code" field at.
 *
 * Reads from .env:
 *   SEPOLIA_RPC_URL         Sepolia RPC endpoint (Alchemy/Infura/public)
 *   GUARDIAN_AGENT_KEY      Private key that owns the address you want
 *                           to brand (the agent's deployer wallet)
 *   GUARDIAN_ENS_NAME       Bare label without ".eth", e.g. "protocol-guardian"
 *   GUARDIAN_ENS_DESC       Optional. Defaults to a sensible string.
 *   GUARDIAN_ENS_GITHUB     Optional. e.g. "janneh2000"
 *   GUARDIAN_ENS_URL        Optional. e.g. "https://protocol-guardian.vercel.app"
 *
 * Usage:
 *   node scripts/register_ens.mjs check        # is the name available?
 *   node scripts/register_ens.mjs commit       # step 1: commit
 *   node scripts/register_ens.mjs register     # step 2: register (>=60s after commit)
 *   node scripts/register_ens.mjs records      # step 3: set text records
 *   node scripts/register_ens.mjs full         # do all three with the right waits
 */

import { createPublicClient, createWalletClient, http, parseEther, namehash, labelhash, keccak256, toHex, encodePacked, encodeFunctionData } from "viem";
import { sepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load .env from repo root.
const envPath = path.resolve(__dirname, "..", ".env");
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^"|"$/g, "");
  }
}

const RPC = process.env.SEPOLIA_RPC_URL;
const KEY = process.env.GUARDIAN_AGENT_KEY;
const LABEL = (process.env.GUARDIAN_ENS_NAME || "").trim().toLowerCase();
const DESC = process.env.GUARDIAN_ENS_DESC || "Autonomous DeFi security agent — pauses vulnerable contracts in real time.";
const GITHUB = process.env.GUARDIAN_ENS_GITHUB || "janneh2000";
const URL = process.env.GUARDIAN_ENS_URL || "https://protocol-guardian.vercel.app";

if (!RPC || !KEY || !LABEL) {
  console.error("Missing one of: SEPOLIA_RPC_URL, GUARDIAN_AGENT_KEY, GUARDIAN_ENS_NAME in .env");
  process.exit(2);
}

// Sepolia ENS deployment addresses (NameWrapper-era).
const REGISTRAR = "0xfb3cE5D01e0f33f41DbB39035dB9745962F1f968"; // ETHRegistrarController (Sepolia)
const REGISTRY  = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e"; // ENS Registry
const PUBLIC_RESOLVER = "0x8FADE66B79cC9f707aB26799354482EB93a5B7dD"; // PublicResolver (Sepolia)

const account = privateKeyToAccount(KEY.startsWith("0x") ? KEY : "0x" + KEY);
const publicClient = createPublicClient({ chain: sepolia, transport: http(RPC) });
const walletClient = createWalletClient({ chain: sepolia, transport: http(RPC), account });

const REGISTRATION_DURATION = BigInt(31536000); // 1 year
const SECRET_FILE = path.resolve(__dirname, "..", ".ens-secret.json");

// ABI fragments we use.
const REG_ABI = [
  { type: "function", name: "available", stateMutability: "view", inputs: [{ name: "name", type: "string" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "rentPrice", stateMutability: "view", inputs: [{ name: "name", type: "string" }, { name: "duration", type: "uint256" }], outputs: [{ components: [{ name: "base", type: "uint256" }, { name: "premium", type: "uint256" }], type: "tuple" }] },
  { type: "function", name: "makeCommitment", stateMutability: "pure", inputs: [
      { name: "name", type: "string" }, { name: "owner", type: "address" }, { name: "duration", type: "uint256" },
      { name: "secret", type: "bytes32" }, { name: "resolver", type: "address" }, { name: "data", type: "bytes[]" },
      { name: "reverseRecord", type: "bool" }, { name: "ownerControlledFuses", type: "uint16" },
    ], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "commit", stateMutability: "nonpayable", inputs: [{ name: "commitment", type: "bytes32" }], outputs: [] },
  { type: "function", name: "register", stateMutability: "payable", inputs: [
      { name: "name", type: "string" }, { name: "owner", type: "address" }, { name: "duration", type: "uint256" },
      { name: "secret", type: "bytes32" }, { name: "resolver", type: "address" }, { name: "data", type: "bytes[]" },
      { name: "reverseRecord", type: "bool" }, { name: "ownerControlledFuses", type: "uint16" },
    ], outputs: [] },
];

const RES_ABI = [
  { type: "function", name: "setText", stateMutability: "nonpayable", inputs: [{ name: "node", type: "bytes32" }, { name: "key", type: "string" }, { name: "value", type: "string" }], outputs: [] },
];

function loadSecret() {
  if (!fs.existsSync(SECRET_FILE)) return null;
  const obj = JSON.parse(fs.readFileSync(SECRET_FILE, "utf8"));
  return obj.label === LABEL ? obj : null;
}

function saveSecret(obj) {
  fs.writeFileSync(SECRET_FILE, JSON.stringify(obj, null, 2));
}

async function check() {
  const available = await publicClient.readContract({
    address: REGISTRAR, abi: REG_ABI, functionName: "available", args: [LABEL],
  });
  const price = await publicClient.readContract({
    address: REGISTRAR, abi: REG_ABI, functionName: "rentPrice", args: [LABEL, REGISTRATION_DURATION],
  });
  const total = price.base + price.premium;
  console.log(`Name: ${LABEL}.eth`);
  console.log(`Available: ${available}`);
  console.log(`Price (1y): ${total.toString()} wei (~${Number(total) / 1e18} ETH)`);
  console.log(`Owner-to-be: ${account.address}`);
  return { available, total };
}

async function commit() {
  const secret = keccak256(toHex(crypto.getRandomValues(new Uint8Array(32))));
  const commitment = await publicClient.readContract({
    address: REGISTRAR, abi: REG_ABI, functionName: "makeCommitment",
    args: [LABEL, account.address, REGISTRATION_DURATION, secret, PUBLIC_RESOLVER, [], true, 0],
  });
  const hash = await walletClient.writeContract({
    address: REGISTRAR, abi: REG_ABI, functionName: "commit", args: [commitment],
  });
  console.log("commit tx:", hash);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log("commit confirmed in block:", receipt.blockNumber.toString());
  saveSecret({ label: LABEL, secret, commitment, committedAt: Date.now() });
  console.log("Secret saved to .ens-secret.json. Wait 60 seconds then run: register");
}

async function register() {
  const saved = loadSecret();
  if (!saved) { console.error("No saved commit for", LABEL, "— run `commit` first."); process.exit(1); }
  const elapsed = Math.floor((Date.now() - saved.committedAt) / 1000);
  if (elapsed < 60) {
    console.error(`Need to wait ${60 - elapsed}s more after commit. Try again shortly.`);
    process.exit(1);
  }
  const { total } = await check();
  const hash = await walletClient.writeContract({
    address: REGISTRAR, abi: REG_ABI, functionName: "register",
    args: [LABEL, account.address, REGISTRATION_DURATION, saved.secret, PUBLIC_RESOLVER, [], true, 0],
    value: total + (total / BigInt(20)), // +5% headroom for price drift
  });
  console.log("register tx:", hash);
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log("registered in block:", receipt.blockNumber.toString());
  console.log(`✓ ${LABEL}.eth now points at ${account.address}.`);
}

async function records() {
  const node = namehash(`${LABEL}.eth`);
  const sets = [
    ["description", DESC],
    ["url", URL],
    ["com.github", GITHUB],
  ];
  for (const [key, value] of sets) {
    const hash = await walletClient.writeContract({
      address: PUBLIC_RESOLVER, abi: RES_ABI, functionName: "setText", args: [node, key, value],
    });
    console.log(`setText(${key}) → ${hash}`);
    await publicClient.waitForTransactionReceipt({ hash });
  }
  console.log("✓ Text records set on", LABEL + ".eth");
}

async function full() {
  const { available } = await check();
  if (!available) { console.error("Name not available."); process.exit(1); }
  await commit();
  console.log("Sleeping 65s for the commit/reveal window…");
  await new Promise((r) => setTimeout(r, 65_000));
  await register();
  await records();
}

const cmd = process.argv[2];
const dispatch = { check, commit, register, records, full };
if (!dispatch[cmd]) {
  console.error("Usage: node scripts/register_ens.mjs <check|commit|register|records|full>");
  process.exit(2);
}
dispatch[cmd]().catch((e) => { console.error(e); process.exit(1); });
