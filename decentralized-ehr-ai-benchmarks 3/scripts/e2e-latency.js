"use strict";
/**
 * End-to-end pipeline latency (Reviewer 3 c.7, Reviewer 4 c.5; manuscript Eq. (3) and Table 7):
 *   T_total = T_encrypt + T_wrap + T_IPFS + T_chain + T_fetch + T_decrypt + T_AI
 *
 *   npx hardhat run scripts/e2e-latency.js                      # in-process Hardhat
 *   npx hardhat run scripts/e2e-latency.js --network sepolia    # public testnet
 * Env:
 *   PAYLOAD_FILE   path to a real input (e.g. an NIH ChestX-ray14 PNG or a DICOM file)
 *   PAYLOAD_MB     size of a random payload if PAYLOAD_FILE is not set (default 10)
 *   IPFS_API       use a real Kubo node (otherwise in-process content-addressed store, labelled)
 *   E2E_RUNS       repetitions (default 10 on hardhat, 3 elsewhere)
 *   AI_LATENCY_S   measured DenseNet121 inference time from your PyTorch script (optional)
 *   MEASURE_FINALITY=1  on Sepolia, also wait until the block is in the `finalized` tag
 * Chain stages report inclusion latency (submit -> receipt with 1 confirmation). Finality is
 * reported separately.
 */
const fs = require("fs");
const path = require("path");
const { ethers, network } = require("hardhat");
const C = require("../lib/ehrCrypto");
const { LocalCASStore, KuboStore } = require("../lib/ipfsStore");
const H = require("../test/helpers");

const now = () => process.hrtime.bigint();
const sec = (t0) => Number(now() - t0) / 1e9;
const MODEL = process.env.MODEL_SHA256 ? "0x" + process.env.MODEL_SHA256.replace(/^0x/, "") : H.bytes32("DenseNet121-e2e-model");

async function waitFinalized(blockNumber) {
  const t0 = now();
  for (;;) {
    const fin = await ethers.provider.getBlock("finalized");
    if (fin && fin.number >= blockNumber) return sec(t0);
    await new Promise((r) => setTimeout(r, 12000));
  }
}

async function main() {
  const isLocal = network.name === "hardhat" || network.name === "localhost";
  const RUNS = Number(process.env.E2E_RUNS || (isLocal ? 10 : 3));
  const store = process.env.IPFS_API ? new KuboStore() : new LocalCASStore();
  const storeLabel = process.env.IPFS_API ? `Kubo ${await store.version()} (${store.api})` : "in-process content-addressed store (NO network I/O)";
  const P = process.env.PAYLOAD_FILE ? fs.readFileSync(process.env.PAYLOAD_FILE) : H.randomPayload(Number(process.env.PAYLOAD_MB || 10) * 1024 * 1024);

  const [deployer] = await ethers.getSigners();
  const registry = process.env.REGISTRY_ADDRESS
    ? await ethers.getContractAt("EHRRegistry", process.env.REGISTRY_ADDRESS)
    : await (await ethers.getContractFactory("EHRRegistry")).deploy(deployer.address);
  await registry.waitForDeployment();
  if (!(await registry.approvedModels(MODEL))) await (await registry.connect(deployer).approveModel(MODEL)).wait();
  const clinician = ethers.Wallet.createRandom(); // never needs gas: its AI authorization is relayed

  const runs = [];
  for (let i = 0; i < RUNS; i++) {
    const recordId = ethers.keccak256(ethers.toUtf8Bytes(`e2e-${Date.now()}-${i}`));
    const s = {};
    let t = now(); const enc = C.encryptPayload(P); s.encrypt = sec(t);
    t = now(); const wk = H.wrapFor(enc.key, clinician, recordId, 1); s.wrap = sec(t);
    t = now(); const cid = await store.add(enc.bundle); s.ipfs = sec(t);
    const input = { recordId, encryptedPayloadCID: cid, payloadDigest: C.hex32(enc.payloadDigest), ciphertextDigest: C.hex32(C.ciphertextDigest(enc.bundle, cid)), signedAt: (await ethers.provider.getBlock("latest")).timestamp };
    const sig = await deployer.signTypedData(await H.domainOf(registry), H.RecordAttestationTypes, { patient: deployer.address, recordId, version: 1, encryptedPayloadCID: cid, payloadDigest: input.payloadDigest, ciphertextDigest: input.ciphertextDigest, timestamp: input.signedAt });
    t = now(); const rcReg = await (await registry.registerRecord(input, sig)).wait(1); s.chainRegister = sec(t);
    t = now(); await (await registry.grantAccess(recordId, clinician.address, true, wk)).wait(1); s.chainGrant = sec(t);
    t = now(); const bundle = await store.cat(cid); s.fetch = sec(t);
    t = now();
    const [, onHp, onHc] = await registry.connect(deployer).getRecord(deployer.address, recordId);
    if (C.hex32(C.ciphertextDigest(bundle, cid)) !== onHc) throw new Error("H_C mismatch");
    s.verify = sec(t);
    t = now();
    const K = C.unwrapKey(wk, clinician.privateKey, { recordId, version: 1, clinicianAddress: clinician.address });
    const plain = C.decryptBundle(bundle, K);
    if (C.hex32(C.sha256(plain)) !== onHp) throw new Error("H_P mismatch");
    s.decrypt = sec(t);
    s.ai = process.env.AI_LATENCY_S ? Number(process.env.AI_LATENCY_S) : null;
    const inf = C.buildInferenceObject(Array.from({ length: 14 }, (_, k) => (k + 1) / 20));
    const aiCid = await store.add(inf.bundle);
    const auth = { patient: deployer.address, recordId, recordVersion: 1n, aiPayloadHash: C.hex32(inf.commitment), encryptedAiCID: aiCid, modelVersionHash: MODEL, clinician: clinician.address, permissionEpoch: 1n, nonce: await registry.nonces(clinician.address), deadline: BigInt((await ethers.provider.getBlock("latest")).timestamp + 3600) };
    const aiSig = await clinician.signTypedData(await H.domainOf(registry), H.DiagnosticAuthorizationTypes, auth);
    t = now(); await (await registry.appendDiagnosticAI(auth, aiSig)).wait(1); s.chainProvenance = sec(t);
    if (!isLocal && process.env.MEASURE_FINALITY === "1") s.finalityRegister = await waitFinalized(rcReg.blockNumber);
    runs.push(s);
    console.log(`run ${i + 1}/${RUNS}`, JSON.stringify(s));
  }

  const keys = ["encrypt", "wrap", "ipfs", "chainRegister", "chainGrant", "fetch", "verify", "decrypt", "ai", "chainProvenance", "finalityRegister"];
  const labels = { encrypt: "T_encrypt  AES-256-GCM encryption", wrap: "T_wrap  ECIES key wrapping (1 recipient)", ipfs: "T_IPFS  upload/pin", chainRegister: "T_chain  registerRecord() inclusion", chainGrant: "T_chain  grantAccess() inclusion", fetch: "T_fetch  IPFS retrieval", verify: "H_C verification vs on-chain value", decrypt: "T_decrypt  ECIES unwrap + AES-GCM decrypt + H_P check", ai: "T_AI  DenseNet121 inference (external measurement)", chainProvenance: "T_chain  appendDiagnosticAI() inclusion", finalityRegister: "Finality of registerRecord block (`finalized` tag)" };
  const stat = (k) => { const a = runs.map((r) => r[k]).filter((x) => typeof x === "number"); if (!a.length) return null; const m = a.reduce((x, y) => x + y, 0) / a.length; const sd = a.length > 1 ? Math.sqrt(a.reduce((q, x) => q + (x - m) ** 2, 0) / (a.length - 1)) : 0; return { m, ci: a.length > 1 ? 1.96 * sd / Math.sqrt(a.length) : 0, n: a.length }; };
  const lines = keys.map((k) => { const s = stat(k); return `| ${labels[k]} | ${s ? `${s.m.toFixed(3)} ± ${s.ci.toFixed(3)} (n=${s.n})` : "not measured"} |`; });
  const totalKeys = ["encrypt", "wrap", "ipfs", "chainRegister", "chainGrant", "fetch", "verify", "decrypt", "ai", "chainProvenance"];
  const total = totalKeys.map(stat).filter(Boolean).reduce((a, s) => a + s.m, 0);
  const dir = path.join(__dirname, "..", "logs"); fs.mkdirSync(dir, { recursive: true });
  const md = [
    `# End-to-end latency on ${network.name} (auto-generated by scripts/e2e-latency.js)`, "",
    `Generated: ${new Date().toISOString()}  `, `Registry: ${await registry.getAddress()}  `,
    `Payload: ${process.env.PAYLOAD_FILE ? process.env.PAYLOAD_FILE : "random"} (${(P.length / 1048576).toFixed(2)} MB)  `,
    `Storage: ${storeLabel}  `, `Recipients: 1; runs: ${RUNS}; chain stages = submit -> 1-confirmation receipt`, "",
    "| Stage | Time (s), mean ± 95% CI |", "|---|---|", ...lines,
    `| **Sum of measured stages** | **${total.toFixed(3)}** |`, "",
  ].join("\n");
  fs.writeFileSync(path.join(dir, `e2e_latency_${network.name}.md`), md);
  console.log(md);
}
main().catch((e) => { console.error(e); process.exitCode = 1; });
