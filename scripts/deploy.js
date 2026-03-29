const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", ethers.utils.formatEther(await deployer.getBalance()), "ETH");

  console.log("\n[1/4] Deploying MockLendingPool...");
  const MockLendingPool = await ethers.getContractFactory("MockLendingPool");
  const pool = await MockLendingPool.deploy();
  await pool.deployed();
  const poolAddress = pool.address;
  console.log("MockLendingPool deployed to:", poolAddress);

  console.log("\n[2/4] Seeding pool with 0.01 ETH liquidity...");
  const seedTx = await pool.deposit({ value: ethers.utils.parseEther("0.01") });
  await seedTx.wait();
  console.log("Pool seeded:", ethers.utils.formatEther(await pool.totalLiquidity()), "ETH");

  console.log("\n[3/4] Deploying ProtocolGuardian...");
  const guardianHotWallet = process.env.GUARDIAN_HOT_WALLET || deployer.address;
  const ProtocolGuardian = await ethers.getContractFactory("ProtocolGuardian");
  const guardian = await ProtocolGuardian.deploy(guardianHotWallet, poolAddress);
  await guardian.deployed();
  const guardianAddress = guardian.address;
  console.log("ProtocolGuardian deployed to:", guardianAddress);

  console.log("\n[4/4] Granting PAUSER_ROLE...");
  const grantTx = await pool.grantPauserRole(guardianAddress);
  await grantTx.wait();
  console.log("PAUSER_ROLE granted.");

  const addresses = { network: "sepolia", deployedAt: new Date().toISOString(), MockLendingPool: poolAddress, ProtocolGuardian: guardianAddress };
  fs.writeFileSync(path.join(__dirname, "../addresses.json"), JSON.stringify(addresses, null, 2));

  const abiDir = path.join(__dirname, "../abi");
  if (!fs.existsSync(abiDir)) fs.mkdirSync(abiDir);
  const poolArtifact = await artifacts.readArtifact("MockLendingPool");
  const guardianArtifact = await artifacts.readArtifact("ProtocolGuardian");
  fs.writeFileSync(path.join(abiDir, "MockLendingPool.json"), JSON.stringify(poolArtifact.abi, null, 2));
  fs.writeFileSync(path.join(abiDir, "ProtocolGuardian.json"), JSON.stringify(guardianArtifact.abi, null, 2));

  console.log("\n✅ Deployment complete!");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("MockLendingPool: ", poolAddress);
  console.log("ProtocolGuardian:", guardianAddress);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("LENDING_POOL_ADDRESS=" + poolAddress);
  console.log("GUARDIAN_CONTRACT_ADDRESS=" + guardianAddress);
}

main().then(() => process.exit(0)).catch((err) => { console.error(err); process.exit(1); });
