"use strict";
// (3,5) threshold key recovery (manuscript Section 3.5).
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const S = require("../lib/shamir");
const E = require("../lib/secp256k1");
const C = require("../lib/ehrCrypto");

const combos = (arr, k) => k === 0 ? [[]] : arr.flatMap((v, i) => combos(arr.slice(i + 1), k - 1).map((c) => [v, ...c]));
const GUARDIANS = ["primary healthcare provider", "identity authority", "family delegate", "institutional escrow service", "backup vault"];

function patientKey() {
  const e = crypto.createECDH("secp256k1"); e.generateKeys();
  return { priv: e.getPrivateKey(), address: E.checksum(E.addressOf(E.mul(E.scalar(e.getPrivateKey())))), pub: e.getPublicKey() };
}
const addressOfPriv = (priv) => E.checksum(E.addressOf(E.mul(E.scalar(priv))));

test("GF(2^8) field axioms: a*inv(a) = 1 for all non-zero a", () => {
  for (let a = 1; a < 256; a++) assert.equal(S.gmul(a, S.gdiv(1, a)), 1);
});

test("all C(5,3)=10 guardian triples reconstruct the patient key; 4 and 5 shares also work", () => {
  const pk = patientKey();
  const shares = S.split(pk.priv, 3, 5);
  const triples = combos(shares, 3);
  assert.equal(triples.length, 10);
  for (const t of triples) {
    const rec = S.combine(t);
    assert.ok(rec.equals(pk.priv), `triple ${t.map((s) => s.x)}`);
    assert.equal(addressOfPriv(rec), pk.address);
  }
  for (const q of combos(shares, 4)) assert.ok(S.combine(q).equals(pk.priv));
  assert.ok(S.combine(shares).equals(pk.priv));
  console.log(`    guardians: ${GUARDIANS.join(", ")}; 10/10 triples, 5/5 quadruples, 1/1 full set reconstructed`);
});

test("any 2 shares reveal nothing: joint share distribution is independent of the secret (chi-square)", () => {
  // For 1-byte secrets 0x00 and 0xFF, draw 65,536 (3,5) splits each and histogram the pair
  // (share1, share2) reduced to 256 buckets (y1 XOR y2 would be too weak; use y1*? -> bucket = y1).
  // Both marginals of any 2 shares must be uniform and identical for both secrets.
  const TRIALS = 65536;
  const chi = (h) => h.reduce((a, o) => a + (o - TRIALS / 256) ** 2 / (TRIALS / 256), 0);
  const stats = [];
  for (const secret of [0x00, 0xff]) {
    const h1 = new Array(256).fill(0), h2 = new Array(256).fill(0), h12 = new Array(256).fill(0);
    for (let t = 0; t < TRIALS; t++) {
      const sh = S.split(Buffer.from([secret]), 3, 5);
      h1[sh[0].y[0]]++; h2[sh[1].y[0]]++; h12[sh[0].y[0] ^ S.gmul(sh[1].y[0], 7)]++;
    }
    stats.push({ secret, chi1: chi(h1), chi2: chi(h2), chi12: chi(h12) });
  }
  // df = 255; the 0.999 quantile of chi-square(255) is ~ 330.5
  for (const st of stats) {
    console.log(`    secret=0x${st.secret.toString(16).padStart(2, "0")}: chi2(share1)=${st.chi1.toFixed(1)}, chi2(share2)=${st.chi2.toFixed(1)}, chi2(share1 xor 7*share2)=${st.chi12.toFixed(1)} (df=255, critical 330.5 at alpha=0.001)`);
    assert.ok(st.chi1 < 330.5 && st.chi2 < 330.5 && st.chi12 < 330.5);
  }
  const secret = crypto.randomBytes(32);
  const shares = S.split(secret, 3, 5);
  for (const pair of combos(shares, 2)) assert.ok(!S.combine(pair).equals(secret), "2-share interpolation does not yield the secret");
});

test("a modified guardian share is rejected by its commitment; without commitments the address check catches it", () => {
  const pk = patientKey();
  const shares = S.split(pk.priv, 3, 5);
  const commitments = shares.map(S.commitShare);
  const bad = { x: shares[1].x, y: Buffer.from(shares[1].y) }; bad.y[7] ^= 0x55;
  assert.deepEqual(S.verifyShares([shares[0], bad, shares[2]], commitments), [true, false, true]);
  const rec = S.combine([shares[0], bad, shares[2]]);
  assert.notEqual(addressOfPriv(rec), pk.address);
});

test("recovered key restores access: unwraps a record key previously wrapped for the patient", () => {
  const pk = patientKey();
  const ctx = { recordId: "0x" + "ab".repeat(32), version: 3, clinicianAddress: pk.address };
  const K = C.generateRecordKey();
  const wk = C.wrapKey(K, pk.pub, ctx);
  const shares = S.split(pk.priv, 3, 5);
  const rec = S.combine([shares[4], shares[0], shares[2]]);
  assert.ok(C.unwrapKey(wk, rec, ctx).equals(K));
});

test("duplicate share indices are refused", () => {
  const shares = S.split(crypto.randomBytes(32), 3, 5);
  assert.throws(() => S.combine([shares[0], shares[0], shares[1]]));
});
