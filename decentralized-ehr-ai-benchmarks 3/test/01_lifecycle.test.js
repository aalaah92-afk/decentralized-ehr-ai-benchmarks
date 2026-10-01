"use strict";
/**
 * Worked record lifecycle (Reviewer 3, comment 3): every serialized value that is hashed,
 * signed, wrapped, stored and verified, printed step by step into the test log.
 */
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const H = require("./helpers");
const { deployFixture, TEST_MODEL_HASH, PROBS } = require("./fixture");

const log = (...a) => console.log("      [lifecycle]", ...a);

describe("01 Worked record lifecycle (register -> grant -> retrieve -> verify -> decrypt -> AI commit)", function () {
  it("executes and verifies the full protocol for one record", async function () {
    const { registry, store, patient, clinA, relayer, recordId, v1 } = await loadFixture(deployFixture);

    log("registry           :", await registry.getAddress());
    log("patient            :", patient.address);
    log("clinician (A)      :", clinA.address);
    log("recordId           :", recordId);
    log("P size (bytes)     :", v1.plaintext.length);
    log("H_P = SHA-256(P)   :", v1.input.payloadDigest);
    log("IPFS bundle        : C||IV||T, bytes =", v1.bundle.length, "(IV 12 B, tag 16 B)");
    log("CID                :", v1.cid);
    log("H_C = SHA-256(C||IV||T||CID):", v1.input.ciphertextDigest);
    log("EIP-712 signature  :", v1.signature);

    // 1. on-chain state after registerRecord
    const [cid, hp, hc, version] = await registry.connect(patient).getRecord(patient.address, recordId);
    expect(cid).to.equal(v1.cid);
    expect(hp).to.equal(v1.input.payloadDigest);
    expect(hc).to.equal(v1.input.ciphertextDigest);
    expect(version).to.equal(1n);
    log("check 1 on-chain CID/H_P/H_C/version match      : PASS");

    // 2. public-key binding + ECIES wrap + grant (CanView + CanEdit)
    H.assertKeyBinding(clinA.signingKey.publicKey, clinA.address);
    log("check 2 keccak(PK_clinician) -> address binding : PASS");
    const wk = H.wrapFor(v1.key, clinA, recordId, 1);
    log("WK_clinician (93 B = R||IV_wrap||C_key||T_key)   :", "0x" + wk.toString("hex"));
    const grantRc = await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, wk)).wait();
    log("grantAccess gasUsed                              :", grantRc.gasUsed.toString());
    const [cv, ce, epoch] = await registry.getPermission(patient.address, recordId, clinA.address);
    expect([cv, ce, epoch]).to.deep.equal([true, true, 1n]);
    log("check 3 CanView=true, CanEdit=true, epoch=1     : PASS");

    // 3. clinician retrieval: CID -> bundle -> H_C check -> unwrap -> decrypt -> H_P check
    const res = await H.clinicianRetrieve({ registry, store, patient: patient.address, recordId, clinician: clinA });
    expect(res.ok, res.reason).to.equal(true);
    expect(res.plaintext.equals(v1.plaintext)).to.equal(true);
    log("check 4 H_C recomputed == on-chain H_C          : PASS");
    log("check 5 ECIES unwrap + AES-256-GCM tag verify   : PASS");
    log("check 6 SHA-256(decrypted P) == on-chain H_P    : PASS");

    // 4. AI inference: encrypted object off-chain, commitment on-chain, relayed submission
    const { auth, signature, inference } = await H.buildDiagnosticAuth({
      registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS,
    });
    log("Hash_infer = SHA-256(Vector_AI||Salt)            :", auth.aiPayloadHash);
    log("CID_infer                                         :", auth.encryptedAiCID);
    log("modelVersionHash                                  :", auth.modelVersionHash);
    const aiRc = await (await registry.connect(relayer).appendDiagnosticAI(auth, signature)).wait();
    log("appendDiagnosticAI (relayed) gasUsed             :", aiRc.gasUsed.toString());
    const rec = await registry.connect(clinA).getInference(patient.address, recordId, 0);
    expect(rec.aiPayloadHash).to.equal(auth.aiPayloadHash);
    expect(rec.reviewingClinician).to.equal(clinA.address);
    expect(rec.recordVersion).to.equal(1n);
    const opened = H.C.openInferenceObject(await store.cat(rec.encryptedAiCID), inference.key);
    expect(H.C.hex32(opened.commitment)).to.equal(rec.aiPayloadHash);
    log("check 7 decrypted AI object re-hashes to on-chain commitment : PASS");

    // 5. confidentiality boundary: the transaction calldata contains no plaintext probability
    const tx = await ethers.provider.getTransaction(aiRc.hash);
    const vecHex = inference.vec.toString("hex");
    expect(tx.data.toLowerCase().includes(vecHex)).to.equal(false);
    log("check 8 plaintext Vector_AI absent from tx calldata          : PASS");
  });
});
