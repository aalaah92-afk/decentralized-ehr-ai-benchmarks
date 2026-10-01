"use strict";
/**
 * Deploy EHRRegistry and register the approved model hash.
 *   MODEL_SHA256=<sha256 of your epoch-28 checkpoint file> npx hardhat run scripts/deploy.js --network sepolia
 * Compute the hash with:  shasum -a 256 densenet121_epoch28.pth
 */
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  const registry = await (await ethers.getContractFactory("EHRRegistry")).deploy(deployer.address);
  const rc = await registry.deploymentTransaction().wait(1);
  const address = await registry.getAddress();
  console.log(`EHRRegistry deployed on ${network.name} at ${address} (gasUsed ${rc.gasUsed}, block ${rc.blockNumber}, tx ${rc.hash})`);
  let modelTx = null;
  if (process.env.MODEL_SHA256) {
    const h = "0x" + process.env.MODEL_SHA256.replace(/^0x/, "");
    modelTx = (await (await registry.approveModel(h)).wait(1)).hash;
    console.log(`approved model ${h} (tx ${modelTx})`);
  }
  const dir = path.join(__dirname, "..", "deployments"); fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${network.name}.json`), JSON.stringify({
    network: network.name, chainId: Number((await ethers.provider.getNetwork()).chainId), address,
    deployTx: rc.hash, block: rc.blockNumber, gasUsed: rc.gasUsed.toString(), deployer: deployer.address,
    modelSha256: process.env.MODEL_SHA256 || null, modelApprovalTx: modelTx, timestamp: new Date().toISOString(),
  }, null, 2));
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
