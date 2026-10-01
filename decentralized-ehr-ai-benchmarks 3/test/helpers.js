"use strict";
const { ethers } = require("hardhat");
const crypto = require("crypto");
const C = require("../lib/ehrCrypto");
const { LocalCASStore } = require("../lib/ipfsStore");

const DOMAIN_NAME = "EHRRegistry";
const DOMAIN_VERSION = "1";

const RecordAttestationTypes = {
  RecordAttestation: [
    { name: "patient", type: "address" },
    { name: "recordId", type: "bytes32" },
    { name: "version", type: "uint64" },
    { name: "encryptedPayloadCID", type: "string" },
    { name: "payloadDigest", type: "bytes32" },
    { name: "ciphertextDigest", type: "bytes32" },
    { name: "timestamp", type: "uint64" },
  ],
};

const DiagnosticAuthorizationTypes = {
  DiagnosticAuthorization: [
    { name: "patient", type: "address" },
    { name: "recordId", type: "bytes32" },
    { name: "recordVersion", type: "uint64" },
    { name: "aiPayloadHash", type: "bytes32" },
    { name: "encryptedAiCID", type: "string" },
    { name: "modelVersionHash", type: "bytes32" },
    { name: "clinician", type: "address" },
    { name: "permissionEpoch", type: "uint64" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

async function domainOf(registry) {
  const { chainId } = await ethers.provider.getNetwork();
  return { name: DOMAIN_NAME, version: DOMAIN_VERSION, chainId, verifyingContract: await registry.getAddress() };
}

/** Funded random wallets (their private keys are needed for ECIES unwrapping). */
async function fundedWallet(funder, eth = "10") {
  const w = ethers.Wallet.createRandom().connect(ethers.provider);
  await (await funder.sendTransaction({ to: w.address, value: ethers.parseEther(eth) })).wait();
  return w;
}

/** Authenticated binding between a clinician address and its secp256k1 encryption key. */
function assertKeyBinding(publicKey, address) {
  if (ethers.computeAddress(publicKey) !== ethers.getAddress(address)) {
    throw new Error("public key does not belong to clinician address");
  }
}

async function latestTimestamp() {
  return (await ethers.provider.getBlock("latest")).timestamp;
}

/**
 * Patient-side preparation of one record version:
 * encrypt P under a fresh K, store C||IV||T, compute H_P / H_C, sign the EIP-712 attestation.
 */
async function prepareRecordVersion({ registry, store, patient, recordId, version, plaintext }) {
  const enc = C.encryptPayload(plaintext);           // fresh K and IV
  const cid = await store.add(enc.bundle);
  const H_C = C.ciphertextDigest(enc.bundle, cid);
  const input = {
    recordId,
    encryptedPayloadCID: cid,
    payloadDigest: C.hex32(enc.payloadDigest),
    ciphertextDigest: C.hex32(H_C),
    signedAt: await latestTimestamp(),
  };
  const signature = await patient.signTypedData(await domainOf(registry), RecordAttestationTypes, {
    patient: patient.address, recordId, version, encryptedPayloadCID: cid,
    payloadDigest: input.payloadDigest, ciphertextDigest: input.ciphertextDigest, timestamp: input.signedAt,
  });
  return { input, signature, key: enc.key, bundle: enc.bundle, cid, plaintext };
}

function wrapFor(K, clinicianWallet, recordId, version) {
  const pub = clinicianWallet.signingKey.publicKey;
  assertKeyBinding(pub, clinicianWallet.address);
  return C.wrapKey(K, pub, { recordId, version, clinicianAddress: clinicianWallet.address });
}

function unwrapAs(wk, clinicianWallet, recordId, version) {
  return C.unwrapKey(wk, clinicianWallet.privateKey, { recordId, version, clinicianAddress: clinicianWallet.address });
}

/**
 * Clinician-side retrieval + verification (Section 3.3 detection component):
 * fetch bundle by CID, recompute H_C and compare with the on-chain value, unwrap K,
 * decrypt, recompute H_P. Returns {ok, reason, plaintext}.
 */
async function clinicianRetrieve({ registry, store, patient, recordId, clinician }) {
  const [cid, payloadDigest, ciphertextDigest, version] = await registry.connect(clinician).getRecord(patient, recordId);
  const bundle = await store.cat(cid);
  const observed = C.hex32(C.ciphertextDigest(bundle, cid));
  if (observed !== ciphertextDigest) return { ok: false, reason: "CIPHERTEXT_DIGEST_MISMATCH", expected: ciphertextDigest, observed, version };
  const [wk, keyVersion] = await registry.connect(clinician).getRecordKey(patient, recordId);
  const K = unwrapAs(Buffer.from(wk.slice(2), "hex"), clinician, recordId, keyVersion);
  let plaintext;
  try { plaintext = C.decryptBundle(bundle, K); } catch { return { ok: false, reason: "GCM_AUTH_FAILURE", version }; }
  const hp = C.hex32(C.sha256(plaintext));
  if (hp !== payloadDigest) return { ok: false, reason: "PAYLOAD_DIGEST_MISMATCH", expected: payloadDigest, observed: hp, version };
  return { ok: true, plaintext, version };
}

async function signDiagnostic({ registry, clinician, auth }) {
  return clinician.signTypedData(await domainOf(registry), DiagnosticAuthorizationTypes, auth);
}

async function buildDiagnosticAuth({ registry, store, patient, recordId, clinician, modelVersionHash, probabilities, deadlineOffset = 3600 }) {
  const inf = C.buildInferenceObject(probabilities);
  const cid = await store.add(inf.bundle);
  const [, , epoch] = await registry.getPermission(patient, recordId, clinician.address);
  const auth = {
    patient, recordId,
    recordVersion: await registry.recordVersion(patient, recordId),
    aiPayloadHash: C.hex32(inf.commitment),
    encryptedAiCID: cid,
    modelVersionHash,
    clinician: clinician.address,
    permissionEpoch: epoch,
    nonce: await registry.nonces(clinician.address),
    deadline: BigInt(await latestTimestamp()) + BigInt(deadlineOffset),
  };
  const signature = await signDiagnostic({ registry, clinician, auth });
  return { auth, signature, inference: inf };
}

const bytes32 = (label) => ethers.keccak256(ethers.toUtf8Bytes(label));
const randomPayload = (n) => crypto.randomBytes(n);

module.exports = {
  C, LocalCASStore, RecordAttestationTypes, DiagnosticAuthorizationTypes, domainOf, fundedWallet,
  assertKeyBinding, latestTimestamp, prepareRecordVersion, wrapFor, unwrapAs, clinicianRetrieve,
  signDiagnostic, buildDiagnosticAuth, bytes32, randomPayload,
};
