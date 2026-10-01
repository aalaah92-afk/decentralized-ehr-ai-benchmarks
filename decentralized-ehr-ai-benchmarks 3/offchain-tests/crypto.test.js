"use strict";
// Off-chain protocol tests (manuscript Section 3.4). Run: node --test offchain-tests/
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const C = require("../lib/ehrCrypto");

const ctx = { recordId: "0x" + "11".repeat(32), version: 1, clinicianAddress: "0x" + "22".repeat(20) };
const clinician = () => { const e = crypto.createECDH("secp256k1"); e.generateKeys(); return e; };

test("AES-256-GCM round trip, 12-byte IV, 16-byte tag, bundle = C||IV||T", () => {
  const P = crypto.randomBytes(1 << 20);
  const e = C.encryptPayload(P);
  assert.equal(e.iv.length, 12); assert.equal(e.T.length, 16); assert.equal(e.key.length, 32);
  assert.equal(e.bundle.length, P.length + 28);
  assert.ok(C.decryptBundle(e.bundle, e.key).equals(P));
  assert.ok(e.payloadDigest.equals(C.sha256(P)));
});

test("tampering with C, IV or T is rejected by GCM and changes H_C", () => {
  const e = C.encryptPayload(crypto.randomBytes(4096));
  const cid = C.cidV1Raw(e.bundle);
  const hc = C.ciphertextDigest(e.bundle, cid);
  for (const [name, idx] of [["C", 5], ["IV", e.bundle.length - 20], ["T", e.bundle.length - 1]]) {
    const t = Buffer.from(e.bundle); t[idx] ^= 1;
    assert.throws(() => C.decryptBundle(t, e.key), undefined, name);
    assert.ok(!C.ciphertextDigest(t, cid).equals(hc), `H_C must change when ${name} changes`);
  }
  assert.ok(!C.ciphertextDigest(e.bundle, cid + "x").equals(hc), "H_C binds the CID");
});

test("fresh key and fresh IV per encryption (100,000 IVs, no collision)", () => {
  const seen = new Set();
  for (let i = 0; i < 100000; i++) seen.add(crypto.randomBytes(12).toString("hex"));
  assert.equal(seen.size, 100000);
  const P = Buffer.from("same payload");
  const a = C.encryptPayload(P), b = C.encryptPayload(P);
  assert.ok(!a.key.equals(b.key)); assert.ok(!a.iv.equals(b.iv)); assert.ok(!a.C.equals(b.C));
});

test("ECIES wrap: 93-byte output, unwrap by recipient, AAD binds record/version/address", () => {
  const cl = clinician(), K = C.generateRecordKey();
  const wk = C.wrapKey(K, cl.getPublicKey(), ctx);
  assert.equal(wk.length, 93);
  assert.ok(C.unwrapKey(wk, cl.getPrivateKey(), ctx).equals(K));
  assert.throws(() => C.unwrapKey(wk, cl.getPrivateKey(), { ...ctx, version: 2 }));
  assert.throws(() => C.unwrapKey(wk, cl.getPrivateKey(), { ...ctx, recordId: "0x" + "33".repeat(32) }));
  assert.throws(() => C.unwrapKey(wk, cl.getPrivateKey(), { ...ctx, clinicianAddress: "0x" + "44".repeat(20) }));
  assert.throws(() => C.unwrapKey(wk, clinician().getPrivateKey(), ctx), "other private key");
  const t = Buffer.from(wk); t[50] ^= 1;
  assert.throws(() => C.unwrapKey(t, cl.getPrivateKey(), ctx), "modified wrapped key");
});

test("ephemeral key differs per wrap (no deterministic wrapping)", () => {
  const cl = clinician(), K = C.generateRecordKey();
  assert.ok(!C.wrapKey(K, cl.getPublicKey(), ctx).equals(C.wrapKey(K, cl.getPublicKey(), ctx)));
});

test("salted AI inference commitment: opens, and hides equal vectors", () => {
  const probs = Array.from({ length: 14 }, (_, i) => i / 14);
  const a = C.buildInferenceObject(probs), b = C.buildInferenceObject(probs);
  const o = C.openInferenceObject(a.bundle, a.key);
  assert.ok(o.commitment.equals(a.commitment));
  assert.ok(!a.commitment.equals(b.commitment), "same vector, different salt -> different commitment");
  o.probabilities.forEach((p, i) => assert.ok(Math.abs(p - probs[i]) < 1e-6));
});

test("CIDv1 raw known-answer (empty block)", () => {
  assert.equal(C.cidV1Raw(Buffer.alloc(0)), "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku");
});
