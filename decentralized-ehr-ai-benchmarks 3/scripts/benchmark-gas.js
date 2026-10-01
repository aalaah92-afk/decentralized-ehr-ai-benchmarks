"use strict";
/**
 * Gas + on-chain storage growth benchmark (manuscript Table 4 and Section 4.1).
 *   npx hardhat run scripts/benchmark-gas.js            (in-process Hardhat network)
 * Env: GAS_ITERATIONS (default 1000), GAS_PRICES_GWEI (default "15,50"), ETH_USD (default 2500)
 * Outputs: logs/gas_benchmark.csv, logs/gas_benchmark.md
 * USD figures are arithmetic projections from the stated gas price / ETH price assumptions,
 * not measured fees.
 */
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");
const H = require("../test/helpers");

const N = Number(process.env.GAS_ITERATIONS || 1000);
const PRICES = (process.env.GAS_PRICES_GWEI || "15,50").split(",").map(Number);
const ETH_USD = Number(process.env.ETH_USD || 2500);
const MODEL = H.bytes32("DenseNet121-benchmark-model");

/** New (zero -> non-zero) storage slots written by a tx => ledger state growth in bytes. */
async function newSlots(txHash, contractAddr) {
  const rc = await ethers.provider.getTransactionReceipt(txHash);
  const trace = await network.provider.send("debug_traceTransaction", [txHash, { disableMemory: true, disableStorage: true }]);
  const keys = new Set();
  for (const s of trace.structLogs) {
    if (s.op === "SSTORE" && s.depth === 1) {
      const k = s.stack[s.stack.length - 1];
      keys.add(ethers.toBeHex(BigInt(k.startsWith("0x") ? k : "0x" + k), 32));
    }
  }
  let created = 0;
  for (const k of keys) {
    const before = await ethers.provider.getStorage(contractAddr, k, rc.blockNumber - 1);
    const after = await ethers.provider.getStorage(contractAddr, k, rc.blockNumber);
    if (BigInt(before) === 0n && BigInt(after) !== 0n) created++;
  }
  return { slotsWritten: keys.size, newSlots: created, bytes: created * 32 };
}

function stats(a) {
  const n = a.length, mean = a.reduce((x, y) => x + y, 0) / n;
  return { n, min: Math.min(...a), max: Math.max(...a), mean };
}

async function main() {
  const [governance, relayer, funder] = await ethers.getSigners();
  const Registry = await ethers.getContractFactory("EHRRegistry");
  const registry = await Registry.deploy(governance.address);
  const deployRc = await registry.deploymentTransaction().wait();
  const addr = await registry.getAddress();
  await (await registry.connect(governance).approveModel(MODEL)).wait();

  const store = new H.LocalCASStore();
  const patient = await H.fundedWallet(funder, "1000");
  const samples = { registerRecord: [], grantAccess: [], revokeAccess: [], updateRecord: [], appendDiagnosticAI: [], reportIntegrityViolation: [] };
  const growth = {};
  const probs = Array.from({ length: 14 }, (_, i) => (i + 1) / 20);

  console.log(`network=${network.name} iterations=${N}`);
  for (let i = 0; i < N; i++) {
    const clin = ethers.Wallet.createRandom();
    const recordId = H.bytes32(`gas-record-${i}`);
    const v1 = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 1, plaintext: H.randomPayload(1024) });
    const r1 = await (await registry.connect(patient).registerRecord(v1.input, v1.signature)).wait();
    samples.registerRecord.push(Number(r1.gasUsed));

    const r2 = await (await registry.connect(patient).grantAccess(recordId, clin.address, true, H.wrapFor(v1.key, clin, recordId, 1))).wait();
    samples.grantAccess.push(Number(r2.gasUsed));

    const { auth, signature } = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clin, modelVersionHash: MODEL, probabilities: probs });
    const r3 = await (await registry.connect(relayer).appendDiagnosticAI(auth, signature)).wait();
    samples.appendDiagnosticAI.push(Number(r3.gasUsed));

    const r4 = await (await registry.connect(patient).reportIntegrityViolation(patient.address, recordId, ethers.encodeBytes32String("CIPHERTEXT_DIGEST_MISMATCH"), H.bytes32("a"), H.bytes32("b"))).wait();
    samples.reportIntegrityViolation.push(Number(r4.gasUsed));

    const r5 = await (await registry.connect(patient).revokeAccess(recordId, clin.address)).wait();
    samples.revokeAccess.push(Number(r5.gasUsed));

    const v2 = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 2, plaintext: H.randomPayload(1024) });
    const r6 = await (await registry.connect(patient).updateRecord(v2.input, v2.signature, [], [])).wait();
    samples.updateRecord.push(Number(r6.gasUsed));

    if (i === 0) {
      growth.registerRecord = await newSlots(r1.hash, addr);
      growth.grantAccess = await newSlots(r2.hash, addr);
      growth.appendDiagnosticAI = await newSlots(r3.hash, addr);
      growth.revokeAccess = await newSlots(r5.hash, addr);
      growth.updateRecord = await newSlots(r6.hash, addr);
    }
    if ((i + 1) % 100 === 0) console.log(`  ${i + 1}/${N}`);
  }

  const dir = path.join(__dirname, "..", "logs");
  fs.mkdirSync(dir, { recursive: true });
  const csv = ["method,iteration,gasUsed"];
  for (const [m, a] of Object.entries(samples)) a.forEach((g, i) => csv.push(`${m},${i},${g}`));
  csv.push(`deployment,0,${deployRc.gasUsed}`);
  fs.writeFileSync(path.join(dir, "gas_benchmark.csv"), csv.join("\n") + "\n");

  const usd = (gas, gwei) => (gas * gwei * 1e-9 * ETH_USD).toFixed(2);
  const md = [
    "# Gas benchmark (auto-generated by scripts/benchmark-gas.js)", "",
    `Generated: ${new Date().toISOString()}  `,
    `Network: ${network.name} (chainId ${(await ethers.provider.getNetwork()).chainId}), solc 0.8.20, optimizer 200 runs  `,
    `Iterations per method: ${N}  `,
    `USD projection assumptions: gas price ${PRICES.join(" / ")} gwei, ETH = ${ETH_USD} USD (projection, not a measured fee)`, "",
    `| Method | n | Gas min | Gas mean | Gas max | ${PRICES.map((p) => `USD @${p} gwei (mean)`).join(" | ")} | New storage slots | State growth (bytes) |`,
    `|---|---|---|---|---|${PRICES.map(() => "---").join("|")}|---|---|`,
    `| Contract deployment | 1 | ${deployRc.gasUsed} | ${deployRc.gasUsed} | ${deployRc.gasUsed} | ${PRICES.map((p) => usd(Number(deployRc.gasUsed), p)).join(" | ")} | – | – |`,
  ];
  for (const [m, a] of Object.entries(samples)) {
    const s = stats(a); const g = growth[m];
    md.push(`| ${m}() | ${s.n} | ${s.min} | ${s.mean.toFixed(1)} | ${s.max} | ${PRICES.map((p) => usd(s.mean, p)).join(" | ")} | ${g ? g.newSlots : "0 (events only)"} | ${g ? g.bytes : 0} |`);
  }
  md.push("", "State growth = number of storage slots changed from zero to non-zero by the first call (x 32 bytes), measured by opcode trace + eth_getStorageAt. Event logs are stored in receipts, not in contract state.");
  fs.writeFileSync(path.join(dir, "gas_benchmark.md"), md.join("\n") + "\n");
  console.log(md.join("\n"));
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
