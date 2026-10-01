"use strict";
/**
 * Prospective revocation semantics (Reviewer 3 c.2, Reviewer 4 c.4, Figure 2):
 * grant -> revoke -> direct retrieval outside the application -> fresh-key update ->
 * re-grant -> recipient addition. Documents what revocation DOES and DOES NOT enforce.
 */
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { loadFixture } = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const H = require("./helpers");
const { deployFixture, TEST_MODEL_HASH, PROBS } = require("./fixture");

const log = (...a) => console.log("      [revocation]", ...a);

describe("02 Prospective revocation, re-keying and re-grant", function () {
  it("CanView and CanEdit coexist; revoke clears both and bumps the epoch; double revoke reverts", async function () {
    const { registry, patient, clinA, recordId, v1 } = await loadFixture(deployFixture);
    await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, H.wrapFor(v1.key, clinA, recordId, 1))).wait();
    expect((await registry.getPermission(patient.address, recordId, clinA.address)).toArray()).to.deep.equal([true, true, 1n]);
    await (await registry.connect(patient).revokeAccess(recordId, clinA.address)).wait();
    expect((await registry.getPermission(patient.address, recordId, clinA.address)).toArray()).to.deep.equal([false, false, 2n]);
    await expect(registry.connect(patient).revokeAccess(recordId, clinA.address)).to.be.revertedWithCustomError(registry, "AccessNotGranted");
    // view-only grant: CanView without CanEdit
    await (await registry.connect(patient).grantAccess(recordId, clinA.address, false, H.wrapFor(v1.key, clinA, recordId, 1))).wait();
    expect((await registry.getPermission(patient.address, recordId, clinA.address)).toArray()).to.deep.equal([true, false, 3n]);
    log("permission transitions (view,edit,epoch): (T,T,1) -> revoke (F,F,2) -> view-only grant (T,F,3) : PASS");
  });

  it("revocation boundary: blocks contract operations and future versions, cannot recall V1 already obtained", async function () {
    const { registry, store, patient, clinA, clinB, relayer, recordId, v1 } = await loadFixture(deployFixture);

    // grant both clinicians on V1; clinician A retrieves V1 while authorized
    await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, H.wrapFor(v1.key, clinA, recordId, 1))).wait();
    await (await registry.connect(patient).grantAccess(recordId, clinB.address, false, H.wrapFor(v1.key, clinB, recordId, 1))).wait();
    const [wkA_v1] = await registry.connect(clinA).getRecordKey(patient.address, recordId);
    const cachedBundleV1 = await store.cat(v1.cid);
    log("clinician A cached WK(V1) and the V1 ciphertext while authorized");

    // revoke A
    await (await registry.connect(patient).revokeAccess(recordId, clinA.address)).wait();
    await expect(registry.connect(clinA).getRecordKey(patient.address, recordId)).to.be.revertedWithCustomError(registry, "Unauthorized");
    await expect(registry.connect(clinA).getRecord(patient.address, recordId)).to.be.revertedWithCustomError(registry, "Unauthorized");
    log("after revoke: getRecordKey / getRecord by A revert (Unauthorized)                        : PASS");

    // an AI append signed by A before revocation is now rejected
    const { auth, signature } = await H.buildDiagnosticAuth({ registry, store, patient: patient.address, recordId, clinician: clinA, modelVersionHash: TEST_MODEL_HASH, probabilities: PROBS });
    await expect(registry.connect(relayer).appendDiagnosticAI(auth, signature)).to.be.revertedWithCustomError(registry, "Unauthorized");
    log("after revoke: appendDiagnosticAI by A reverts (Unauthorized)                               : PASS");

    // wrapped key for the current version was deleted from contract storage
    const clinB_view = await registry.connect(clinB).getRecordKey(patient.address, recordId);
    expect(clinB_view[0]).to.not.equal("0x");
    log("clinician B (still authorized) unaffected                                                  : PASS");

    // HONEST BOUNDARY: A can still decrypt V1 offline from material obtained before revocation
    const K1 = H.unwrapAs(Buffer.from(wkA_v1.slice(2), "hex"), clinA, recordId, 1);
    expect(H.C.decryptBundle(cachedBundleV1, K1).equals(v1.plaintext)).to.equal(true);
    log("BOUNDARY: A decrypts previously obtained V1 offline (cannot be recalled)                   : CONFIRMED");

    // patient publishes V2 under a fresh key K2, wrapping only for active viewers
    const v2 = await H.prepareRecordVersion({ registry, store, patient, recordId, version: 2, plaintext: H.randomPayload(512 * 1024) });
    expect(v2.key.equals(v1.key)).to.equal(false);
    // attempting to include the revoked clinician is rejected on-chain
    await expect(
      registry.connect(patient).updateRecord(v2.input, v2.signature, [clinA.address], [H.wrapFor(v2.key, clinA, recordId, 2)])
    ).to.be.revertedWithCustomError(registry, "AccessNotGranted");
    await (await registry.connect(patient).updateRecord(v2.input, v2.signature, [clinB.address], [H.wrapFor(v2.key, clinB, recordId, 2)])).wait();
    expect(await registry.recordVersion(patient.address, recordId)).to.equal(2n);
    log("V2 published with fresh K2 != K1; wrapping K2 for revoked A rejected (AccessNotGranted)   : PASS");

    // direct retrieval outside the application: A fetches V2 ciphertext straight from IPFS
    const bundleV2 = await store.cat(v2.cid); // CIDs are public on-chain (event logs / storage)
    expect(() => H.C.decryptBundle(bundleV2, K1)).to.throw();
    log("direct IPFS fetch of V2 by A + decrypt with old K1 -> GCM authentication failure         : PASS");
    // and no wrapped key for A exists for V2 (even a spoofed eth_call `from` cannot return one)
    await expect(registry.connect(clinA).getRecordKey(patient.address, recordId)).to.be.revertedWithCustomError(registry, "Unauthorized");

    // clinician B retrieves V2 normally
    const resB = await H.clinicianRetrieve({ registry, store, patient: patient.address, recordId, clinician: clinB });
    expect(resB.ok, resB.reason).to.equal(true);
    expect(resB.version).to.equal(2n);
    log("clinician B retrieves and verifies V2                                                      : PASS");

    // re-grant A on V2: new epoch, new wrapped key for K2
    await (await registry.connect(patient).grantAccess(recordId, clinA.address, true, H.wrapFor(v2.key, clinA, recordId, 2))).wait();
    const resA = await H.clinicianRetrieve({ registry, store, patient: patient.address, recordId, clinician: clinA });
    expect(resA.ok, resA.reason).to.equal(true);
    expect((await registry.getPermission(patient.address, recordId, clinA.address))[2]).to.equal(3n);
    log("re-grant A (epoch 3) -> A retrieves V2                                                     : PASS");

    // the pre-revocation AI authorization of A (epoch 1) stays invalid after re-grant
    await expect(registry.connect(relayer).appendDiagnosticAI(auth, signature)).to.be.revertedWithCustomError(registry, "StaleRecordVersion");
    const stale = { ...auth, recordVersion: 2n };
    const staleSig = await H.signDiagnostic({ registry, clinician: clinA, auth: stale });
    await expect(registry.connect(relayer).appendDiagnosticAI(stale, staleSig)).to.be.revertedWithCustomError(registry, "StalePermissionEpoch");
    log("authorization signed under epoch 1 rejected after re-grant (StalePermissionEpoch)         : PASS");
  });

  it("recipient addition on the current version (new clinician C) without re-encryption", async function () {
    const { registry, store, patient, funder, recordId, v1 } = await loadFixture(deployFixture);
    const clinC = await H.fundedWallet(funder);
    await (await registry.connect(patient).grantAccess(recordId, clinC.address, false, H.wrapFor(v1.key, clinC, recordId, 1))).wait();
    const res = await H.clinicianRetrieve({ registry, store, patient: patient.address, recordId, clinician: clinC });
    expect(res.ok, res.reason).to.equal(true);
    log("recipient added via grantAccess with WK_C for current version                            : PASS");
  });

  it("wrapped key is bound to (recordId, version, clinician) through GCM AAD", async function () {
    const { patient, clinA, recordId, v1 } = await loadFixture(deployFixture);
    const wk = H.wrapFor(v1.key, clinA, recordId, 1);
    expect(() => H.unwrapAs(wk, clinA, recordId, 2)).to.throw();
    expect(() => H.unwrapAs(wk, clinA, H.bytes32("other-record"), 1)).to.throw();
    const imposter = ethers.Wallet.createRandom();
    expect(() => H.C.unwrapKey(wk, imposter.privateKey, { recordId, version: 1, clinicianAddress: clinA.address })).to.throw();
    expect(patient.address).to.be.properAddress;
    log("wrapped key rejected for wrong version / record / private key                            : PASS");
  });
});
