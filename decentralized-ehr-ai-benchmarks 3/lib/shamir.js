"use strict";
/**
 * (k, n) threshold key escrow with Shamir's Secret Sharing over GF(2^8) (manuscript Section 3.5).
 * Field: GF(2^8) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11b).
 * Each byte of the secret is shared with an independent random polynomial of degree k-1;
 * share i is evaluated at x = i (1..n).
 *
 * Verifiability (the "valid cryptographic proofs" of Section 3.5):
 *   - at split time, a SHA-256 commitment c_i = SHA-256("EHR-SSS" || i || share_i) of every share
 *     is published (e.g. in the escrow record), so a guardian cannot submit a modified share;
 *   - after reconstruction, the recovered secp256k1 private key is accepted only if its public key
 *     maps to the patient's registered address.
 */
const crypto = require("crypto");

const EXP = new Uint8Array(510), LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x ^= (x << 1) ^ (x & 0x80 ? 0x1b : 0); // multiply by generator 3
    x &= 0xff;
  }
  for (let i = 255; i < 510; i++) EXP[i] = EXP[i - 255];
})();
const gmul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
const gdiv = (a, b) => { if (b === 0) throw new Error("division by zero"); return a === 0 ? 0 : EXP[(LOG[a] + 255 - LOG[b]) % 255]; };

function evalPoly(coeffs, x) { // Horner, coeffs[0] = secret byte
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) y = gmul(y, x) ^ coeffs[i];
  return y;
}

function split(secret, k, n) {
  if (!(k >= 2 && k <= n && n <= 255)) throw new Error("require 2 <= k <= n <= 255");
  const shares = Array.from({ length: n }, (_, i) => ({ x: i + 1, y: Buffer.alloc(secret.length) }));
  for (let b = 0; b < secret.length; b++) {
    const coeffs = [secret[b], ...crypto.randomBytes(k - 1)];
    for (const s of shares) s.y[b] = evalPoly(coeffs, s.x);
  }
  return shares;
}

/** Lagrange interpolation at x = 0. */
function combine(shares) {
  const xs = shares.map((s) => s.x);
  if (new Set(xs).size !== xs.length) throw new Error("duplicate share index");
  const len = shares[0].y.length;
  const out = Buffer.alloc(len);
  for (let b = 0; b < len; b++) {
    let acc = 0;
    for (let i = 0; i < shares.length; i++) {
      let num = 1, den = 1;
      for (let j = 0; j < shares.length; j++) {
        if (i === j) continue;
        num = gmul(num, xs[j]);
        den = gmul(den, xs[i] ^ xs[j]);
      }
      acc ^= gmul(shares[i].y[b], gdiv(num, den));
    }
    out[b] = acc;
  }
  return out;
}

const commitShare = (s) => crypto.createHash("sha256").update(Buffer.concat([Buffer.from("EHR-SSS"), Buffer.from([s.x]), s.y])).digest("hex");

function verifyShares(shares, commitments) {
  return shares.map((s) => commitments[s.x - 1] === commitShare(s));
}

module.exports = { split, combine, commitShare, verifyShares, gmul, gdiv, evalPoly };
