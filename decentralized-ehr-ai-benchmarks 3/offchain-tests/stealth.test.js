"use strict";
// Stealth recipient addresses (ERC-5564 secp256k1 scheme) for access grants (manuscript Section 5.3).
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const ST = require("../lib/stealth");
const E = require("../lib/secp256k1");
const C = require("../lib/ehrCrypto");

test("clinician recognises its announcement and derives the stealth private key", () => {
  const clin = ST.generateMetaAddress();
  const ann = ST.generateStealthAddress(clin.meta);
  const priv = ST.checkAndDerive(ann, clin.viewPriv, clin.spendPriv);
  assert.ok(priv);
  const e = crypto.createECDH("secp256k1"); e.setPrivateKey(priv);
  assert.ok(e.getPublicKey().equals(ann.stealthPub), "OpenSSL cross-check of derived key");
});

test("another clinician cannot recognise or use the announcement", () => {
  const a = ST.generateMetaAddress(), b = ST.generateMetaAddress();
  let recognised = 0;
  for (let i = 0; i < 200; i++) if (ST.checkAndDerive(ST.generateStealthAddress(a.meta), b.viewPriv, b.spendPriv)) recognised++;
  assert.equal(recognised, 0);
});

test("view key alone cannot spend: wrong spend key gives a different address", () => {
  const a = ST.generateMetaAddress();
  const ann = ST.generateStealthAddress(a.meta);
  assert.equal(ST.checkAndDerive(ann, a.viewPriv, ST.randomScalar()), null);
});

test("record key wrapped for the stealth public key is unwrapped with the derived key", () => {
  const clin = ST.generateMetaAddress();
  const ann = ST.generateStealthAddress(clin.meta);
  const ctx = { recordId: "0x" + "cd".repeat(32), version: 1, clinicianAddress: ann.stealthAddress };
  const K = C.generateRecordKey();
  const wk = C.wrapKey(K, ann.stealthPub, ctx);
  const priv = ST.checkAndDerive(ann, clin.viewPriv, clin.spendPriv);
  assert.ok(C.unwrapKey(wk, priv, ctx).equals(K));
});

test("1,000 grants to the same clinician produce 1,000 distinct recipient addresses", () => {
  const clin = ST.generateMetaAddress();
  const addrs = new Set();
  for (let i = 0; i < 1000; i++) addrs.add(ST.generateStealthAddress(clin.meta).stealthAddress);
  assert.equal(addrs.size, 1000);
});
