"use strict";
/**
 * Adversarial security evaluation (manuscript Section 4.1.1 / Table 5; Reviewer 3 c.4;
 * Reviewer 4 c.11). Each case records EXPECTED vs OBSERVED outcomes into
 * logs/security_test_matrix.md via test/recorder.js.
 */
const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const H = require("./helpers");
const R = require("./recorder");
const { deployFixture, TEST_MODEL_HASH, PROBS } = require("./fixture");

async function check(registry, row, fn) {
  const observed = await R.outcomeOf(registry, fn);
  R.add({ ...row, observed });
  expect(observed, `${row.id}: ${row.action}`).to.equal(row.expected);
}

async function granted() {
  const f = await loadFixture(deployFixture);
  const { registry, patient, clinA, clinB, recordId, v1 } = f;
  await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, H.wrapFor(v1.key, clinA, recordId, 1))).wait();
  await (await registry.connect(patient).grantAccess(recordId, clinB.address, false, H.wrapFor(v1.key, clinB, recordId, 1))).wait();
  return f;
}

/** Client-side detection -> separate successful reporting transaction (Section 3.3). */
async function detectAndReport({ registry, store, patient, recordId, clinician }) {
  const res = await H.clinicianRetrieve({ registry, store, patient: patient.address, recordId, clinician });
  if (res.ok) return { res, receipt: null };
  const tx = await registry.connect(clinician).reportIntegrityViolation(
    patient.address, recordId, ethers.encodeBytes32String(res.reason), res.expected ?? ethers.ZeroHash, res.observed ?? H.bytes32(res.reason)
  );
  return { res, receipt: await tx.wait() };
}

function alertIn(registry, receipt) {
  return receipt.logs.map((l) => { try { return registry.interface.parseLog(l); } catch { return null; } })
    .find((e) => e && e.name === "IntegrityViolationAlert");
}

async function countExternalCalls(txHash) {
  const trace = await network.provider.send("debug_traceTransaction", [txHash, { disableStorage: true, disableMemory: true }]);
  const calls = [];
  for (const s of trace.structLogs) {
    if (["CALL", "DELEGATECALL", "CALLCODE", "STATICCALL"].includes(s.op)) {
      const st = s.stack; const addr = st[st.length - 2];
      calls.push({ op: s.op, to: BigInt(addr.startsWith("0x") ? addr : "0x" + addr) });
    }
  }
  return calls;
}

describe("03 Adversarial security test matrix", function () {
  after(() => R.write());

  // ----------------------------------------------------------------------- ST-01
  it("ST-01 unauthorized / cross-patient access", async function () {
    const { registry, patient, patientB, clinA, outsider, recordId } = await granted();
    await check(registry, { id: "ST-01a", vector: "Unauthorized access", action: "Non-permissioned account calls getRecordKey()", expected: "REVERT:Unauthorized" },
      () => registry.connect(outsider).getRecordKey(patient.address, recordId));
    await check(registry, { id: "ST-01b", vector: "Unauthorized access", action: "Non-permissioned account calls getRecord()", expected: "REVERT:Unauthorized" },
      () => registry.connect(outsider).getRecord(patient.address, recordId));
    await check(registry, { id: "ST-01c", vector: "Cross-patient access", action: "Patient B calls grantAccess() on patient A's recordId", expected: "REVERT:Unauthorized" },
      () => registry.connect(patientB).grantAccess(recordId, outsider.address, true, Buffer.alloc(93, 1)));
    await check(registry, { id: "ST-01d", vector: "Cross-patient access", action: "Patient B calls revokeAccess() for A's clinician", expected: "REVERT:Unauthorized" },
      () => registry.connect(patientB).revokeAccess(recordId, clinA.address));
    await check(registry, { id: "ST-01e", vector: "Unauthorized access", action: "Outsider submits reportIntegrityViolation() (no event persists)", expected: "REVERT:Unauthorized" },
      () => registry.connect(outsider).reportIntegrityViolation(patient.address, recordId, H.bytes32("X"), H.bytes32("a"), H.bytes32("b")));
  });

  it("ST-01 view/edit separation", async function () {
    const { registry, store, patient, clinB, relayer, recordId } = await granted();
    const { auth, signature } = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinB, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    await check(registry, { id: "ST-01f", vector: "View/edit separation", action: "View-only clinician appends AI inference", expected: "REVERT:Unauthorized" },
      () => registry.connect(relayer).appendDiagnosticAI(auth, signature));
  });

  // ----------------------------------------------------------------------- ST-02
  it("ST-02 payload / ciphertext / CID tampering -> client detection -> persistent alert", async function () {
    const cases = [
      { id: "ST-02a", action: "Flip one byte of ciphertext C on the IPFS node", mutate: (b) => { b[10] ^= 0xff; return b; }, reason: "CIPHERTEXT_DIGEST_MISMATCH" },
      { id: "ST-02b", action: "Flip one byte of GCM tag T on the IPFS node", mutate: (b) => { b[b.length - 1] ^= 0x01; return b; }, reason: "CIPHERTEXT_DIGEST_MISMATCH" },
      { id: "ST-02c", action: "Flip one byte of IV on the IPFS node", mutate: (b) => { b[b.length - 20] ^= 0x01; return b; }, reason: "CIPHERTEXT_DIGEST_MISMATCH" },
    ];
    for (const c of cases) {
      const { registry, store, patient, clinA, recordId, v1 } = await granted();
      const restore = store.tamper(v1.cid, c.mutate);
      const { res, receipt } = await detectAndReport({ registry, store, patient, recordId, clinician: clinA });
      restore();
      const ev = receipt && alertIn(registry, receipt);
      const observed = !res.ok && ev ? `DETECTED:${res.reason}+IntegrityViolationAlert` : `NOT_DETECTED`;
      R.add({ id: c.id, vector: "Ciphertext tampering", action: c.action, expected: `DETECTED:${c.reason}+IntegrityViolationAlert`, observed });
      expect(observed).to.equal(`DETECTED:${c.reason}+IntegrityViolationAlert`);
      expect(ev.args.expectedDigest).to.equal(v1.input.ciphertextDigest);
    }

    // CID substitution: storage node serves a different (validly encrypted) object for the CID
    {
      const { registry, store, patient, clinA, recordId, v1 } = await granted();
      const other = H.C.encryptPayload(H.randomPayload(1024));
      const restore = store.tamper(v1.cid, () => other.bundle);
      const { res, receipt } = await detectAndReport({ registry, store, patient, recordId, clinician: clinA });
      restore();
      const observed = !res.ok && alertIn(registry, receipt) ? `DETECTED:${res.reason}+IntegrityViolationAlert` : "NOT_DETECTED";
      R.add({ id: "ST-02d", vector: "CID substitution", action: "Storage node returns a different encrypted object for the registered CID", expected: "DETECTED:CIPHERTEXT_DIGEST_MISMATCH+IntegrityViolationAlert", observed });
      expect(observed).to.equal("DETECTED:CIPHERTEXT_DIGEST_MISMATCH+IntegrityViolationAlert");
    }

    // Payload hash tampering H_P' != H_P (registered image-identity commitment does not match content)
    {
      const { registry, store, patient, clinA } = await loadFixture(deployFixture);
      const recordId = H.bytes32("record-hp-tamper");
      const v = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 1, plaintext: H.randomPayload(4096) });
      const forged = { ...v.input, payloadDigest: H.C.hex32(H.C.sha256(Buffer.from("different DICOM"))) };
      const domain = await H.domainOf(registry);
      const sig = await patient.signTypedData(domain, H.RecordAttestationTypes, {
        patient: patient.address, recordId, version: 1, encryptedPayloadCID: forged.encryptedPayloadCID,
        payloadDigest: forged.payloadDigest, ciphertextDigest: forged.ciphertextDigest, timestamp: forged.signedAt,
      });
      await (await registry.connect(patient).registerRecord(forged, sig)).wait();
      await (await registry.connect(patient).grantAccess(recordId, clinA.address, false, H.wrapFor(v.key, clinA, recordId, 1))).wait();
      const { res, receipt } = await detectAndReport({ registry, store, patient, recordId, clinician: clinA });
      const observed = !res.ok && alertIn(registry, receipt) ? `DETECTED:${res.reason}+IntegrityViolationAlert` : "NOT_DETECTED";
      R.add({ id: "ST-02e", vector: "Payload hash tampering", action: "Registered H_P' != SHA-256(decrypted P)", expected: "DETECTED:PAYLOAD_DIGEST_MISMATCH+IntegrityViolationAlert", observed });
      expect(observed).to.equal("DETECTED:PAYLOAD_DIGEST_MISMATCH+IntegrityViolationAlert");
    }
  });

  // ----------------------------------------------------------------------- ST-03
  it("ST-03 re-entrancy surface: no external calls in access-control functions (opcode trace)", async function () {
    const { registry, store, patient, clinA, clinB, relayer, recordId, v1 } = await granted();
    const revokeTx = await registry.connect(patient).revokeAccess(recordId, clinB.address);
    await revokeTx.wait();
    const grantTx = await registry.connect(patient).grantAccess(recordId, clinB.address, false, H.wrapFor(v1.key, clinB, recordId, 1));
    await grantTx.wait();
    const { auth, signature } = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    const aiTx = await registry.connect(relayer).appendDiagnosticAI(auth, signature);
    await aiTx.wait();

    const describeCalls = (calls) => calls.length === 0 ? "0 external calls"
      : calls.every((c) => c.op === "STATICCALL" && c.to === 1n) ? `${calls.length} STATICCALL to ecrecover precompile (0x01) only` : `EXTERNAL:${JSON.stringify(calls.map((c) => [c.op, c.to.toString(16)]))}`;

    const obsRevoke = describeCalls(await countExternalCalls(revokeTx.hash));
    R.add({ id: "ST-03a", vector: "Re-entrancy", action: "Opcode trace of revokeAccess() for CALL/DELEGATECALL/CALLCODE/STATICCALL", expected: "0 external calls", observed: obsRevoke });
    expect(obsRevoke).to.equal("0 external calls");
    const obsGrant = describeCalls(await countExternalCalls(grantTx.hash));
    R.add({ id: "ST-03b", vector: "Re-entrancy", action: "Opcode trace of grantAccess()", expected: "0 external calls", observed: obsGrant });
    expect(obsGrant).to.equal("0 external calls");
    const obsAi = describeCalls(await countExternalCalls(aiTx.hash));
    R.add({ id: "ST-03c", vector: "Re-entrancy", action: "Opcode trace of appendDiagnosticAI()", expected: "1 STATICCALL to ecrecover precompile (0x01) only", observed: obsAi });
    expect(obsAi).to.equal("1 STATICCALL to ecrecover precompile (0x01) only");
    // state preserved: permissions unchanged by the traced calls beyond their intended effect
    expect((await registry.getPermission(patient.address, recordId, clinB.address)).toArray()).to.deep.equal([true, false, 3n]);
  });

  // ----------------------------------------------------------------------- ST-04
  it("ST-04 signature replay, expiry, epoch and forgery", async function () {
    const { registry, store, patient, clinA, outsider, relayer, recordId, v1 } = await granted();
    const b = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    await check(registry, { id: "ST-04a", vector: "Baseline", action: "Valid clinician-signed AI authorization (relayed)", expected: "SUCCESS" },
      () => registry.connect(relayer).appendDiagnosticAI(b.auth, b.signature));
    await check(registry, { id: "ST-04b", vector: "Signature replay", action: "Re-submit the identical signed authorization", expected: "REVERT:Replay" },
      () => registry.connect(relayer).appendDiagnosticAI(b.auth, b.signature));

    const e = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS, deadlineOffset: 60 });
    await network.provider.send("evm_increaseTime", [120]);
    await network.provider.send("evm_mine");
    await check(registry, { id: "ST-04c", vector: "Expired authorization", action: "Submit authorization after its deadline", expected: "REVERT:AuthorizationExpired" },
      () => registry.connect(relayer).appendDiagnosticAI(e.auth, e.signature));

    const f = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    await check(registry, { id: "ST-04d", vector: "Invalid signature", action: "Authorization for clinician A signed by outsider key", expected: "REVERT:InvalidSignature" },
      async () => registry.connect(relayer).appendDiagnosticAI(f.auth, await H.signDiagnostic({ registry, clinician: outsider, auth: f.auth })));
    await check(registry, { id: "ST-04e", vector: "Parameter tampering", action: "Change aiPayloadHash after clinician signed", expected: "REVERT:InvalidSignature" },
      () => registry.connect(relayer).appendDiagnosticAI({ ...f.auth, aiPayloadHash: H.bytes32("tampered") }, f.signature));
    await check(registry, { id: "ST-04f", vector: "Malformed signature", action: "65 random bytes as signature", expected: "REVERT:InvalidSignature" },
      () => registry.connect(relayer).appendDiagnosticAI(f.auth, ethers.hexlify(ethers.randomBytes(65))));

    // stale permission epoch: sign, then revoke + re-grant
    await (await registry.connect(patient).revokeAccess(recordId, clinA.address)).wait();
    await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, H.wrapFor(v1.key, clinA, recordId, 1))).wait();
    await check(registry, { id: "ST-04g", vector: "Stale authorization epoch", action: "Authorization signed before revoke/re-grant", expected: "REVERT:StalePermissionEpoch" },
      () => registry.connect(relayer).appendDiagnosticAI(f.auth, f.signature));
  });

  it("ST-04 record-signature replay and forgery", async function () {
    const { registry, store, patient, outsider, recordId, v1 } = await loadFixture(deployFixture);
    await check(registry, { id: "ST-04h", vector: "Record replay", action: "Re-submit registerRecord() with the same signed attestation", expected: "REVERT:RecordAlreadyExists" },
      () => registry.connect(patient).registerRecord(v1.input, v1.signature));
    const rid = H.bytes32("record-forged");
    const v = await H.prepareRecordVersion({ registry, store, patient, recordId: rid, version: 1, plaintext: H.randomPayload(2048) });
    await check(registry, { id: "ST-04i", vector: "Signature forgery", action: "Outsider submits registerRecord() with patient's signature", expected: "REVERT:InvalidSignature" },
      () => registry.connect(outsider).registerRecord(v.input, v.signature));
    // version binding: V2 signature cannot be replayed to create V3
    const v2 = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 2, plaintext: H.randomPayload(2048) });
    await (await registry.connect(patient).updateRecord(v2.input, v2.signature, [], [])).wait();
    await check(registry, { id: "ST-04j", vector: "Version replay", action: "Replay V2 update signature to create V3", expected: "REVERT:InvalidSignature" },
      () => registry.connect(patient).updateRecord(v2.input, v2.signature, [], []));
    // cross-contract replay (EIP-712 domain separation)
    const [governance] = await ethers.getSigners();
    const other = await (await ethers.getContractFactory("EHRRegistry")).deploy(governance.address);
    await check(other, { id: "ST-04k", vector: "Cross-contract replay", action: "Replay V1 attestation on a second registry deployment", expected: "REVERT:InvalidSignature" },
      () => other.connect(patient).registerRecord(v1.input, v1.signature));
  });

  // ----------------------------------------------------------------------- ST-05
  it("ST-05 unauthorized key insertion", async function () {
    const { registry, store, patient, clinA, outsider, recordId, v1 } = await loadFixture(deployFixture);
    await check(registry, { id: "ST-05a", vector: "Unauthorized key insertion", action: "Non-owner calls grantAccess() to insert a wrapped key", expected: "REVERT:Unauthorized" },
      () => registry.connect(outsider).grantAccess(recordId, outsider.address, true, H.wrapFor(v1.key, outsider, recordId, 1)));
    const v2 = await H.prepareRecordVersion({ registry, store, patient: outsider, recordId, version: 2, plaintext: H.randomPayload(2048) });
    await check(registry, { id: "ST-05b", vector: "Unauthorized key insertion", action: "Non-owner calls updateRecord() on patient's record", expected: "REVERT:Unauthorized" },
      () => registry.connect(outsider).updateRecord(v2.input, v2.signature, [], []));
    const v2p = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 2, plaintext: H.randomPayload(2048) });
    await check(registry, { id: "ST-05c", vector: "Key for non-granted recipient", action: "Patient wraps K2 for a clinician without CanView", expected: "REVERT:AccessNotGranted" },
      () => registry.connect(patient).updateRecord(v2p.input, v2p.signature, [clinA.address], [H.wrapFor(v2p.key, clinA, recordId, 2)]));
    await check(registry, { id: "ST-05d", vector: "Malformed wrapped key", action: "grantAccess() with 64-byte wrapped key", expected: "REVERT:InvalidInput" },
      () => registry.connect(patient).grantAccess(recordId, clinA.address, false, Buffer.alloc(64, 7)));
  });

  // ----------------------------------------------------------------------- ST-06
  it("ST-06 inconsistent record / model identifiers", async function () {
    const { registry, store, patient, clinA, relayer, recordId } = await granted();
    const good = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    const unapproved = { ...good.auth, modelVersionHash: H.bytes32("unregistered-model") };
    await check(registry, { id: "ST-06a", vector: "Unapproved model identifier", action: "AI commitment with unregistered modelVersionHash", expected: "REVERT:ModelNotApproved" },
      async () => registry.connect(relayer).appendDiagnosticAI(unapproved, await H.signDiagnostic({ registry, clinician: clinA, auth: unapproved })));
    const wrongVer = { ...good.auth, recordVersion: 7n };
    await check(registry, { id: "ST-06b", vector: "Inconsistent record version", action: "AI commitment referencing non-current record version", expected: "REVERT:StaleRecordVersion" },
      async () => registry.connect(relayer).appendDiagnosticAI(wrongVer, await H.signDiagnostic({ registry, clinician: clinA, auth: wrongVer })));
    const noRec = { ...good.auth, recordId: H.bytes32("does-not-exist") };
    await check(registry, { id: "ST-06c", vector: "Unknown record identifier", action: "AI commitment for non-existent recordId", expected: "REVERT:RecordNotFound" },
      async () => registry.connect(relayer).appendDiagnosticAI(noRec, await H.signDiagnostic({ registry, clinician: clinA, auth: noRec })));
  });

  // ----------------------------------------------------------------------- ST-07
  it("ST-07 administrative privilege escalation", async function () {
    const { registry, governance, patient, outsider, recordId } = await loadFixture(deployFixture);
    await check(registry, { id: "ST-07a", vector: "Admin privilege escalation", action: "Non-governance account calls approveModel()", expected: "REVERT:OwnableUnauthorizedAccount" },
      () => registry.connect(outsider).approveModel(H.bytes32("rogue-model")));
    await check(registry, { id: "ST-07b", vector: "Admin override of patient consent", action: "Governance (owner) calls grantAccess() on a patient record", expected: "REVERT:Unauthorized" },
      () => registry.connect(governance).grantAccess(recordId, outsider.address, true, Buffer.alloc(93, 1)));
    await check(registry, { id: "ST-07c", vector: "Admin override of patient consent", action: "Governance (owner) calls revokeAccess() on a patient record", expected: "REVERT:Unauthorized" },
      () => registry.connect(governance).revokeAccess(recordId, outsider.address));
    expect(patient.address).to.be.properAddress;
  });

  // ----------------------------------------------------------------------- ST-08
  it("ST-08 revoked access", async function () {
    const { registry, patient, clinA, recordId } = await granted();
    await (await registry.connect(patient).revokeAccess(recordId, clinA.address)).wait();
    await check(registry, { id: "ST-08a", vector: "Revoked access", action: "Revoked clinician calls getRecordKey()", expected: "REVERT:Unauthorized" },
      () => registry.connect(clinA).getRecordKey(patient.address, recordId));
    await check(registry, { id: "ST-08b", vector: "Revoked access", action: "Revoked clinician calls getRecord()", expected: "REVERT:Unauthorized" },
      () => registry.connect(clinA).getRecord(patient.address, recordId));
    await check(registry, { id: "ST-08c", vector: "Revocation of non-granted address", action: "Patient revokes an address that holds no permission", expected: "REVERT:AccessNotGranted" },
      () => registry.connect(patient).revokeAccess(recordId, clinA.address));
  });
});
