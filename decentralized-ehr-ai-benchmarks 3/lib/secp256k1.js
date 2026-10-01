"use strict";
/**
 * secp256k1 point arithmetic (affine, BigInt) used by the stealth-address module.
 * Reference/teaching implementation: NOT constant-time. Production clients should use an
 * audited library (e.g. @noble/secp256k1); the tests cross-check it against OpenSSL (Node ECDH).
 */
const { keccak256 } = require("./keccak");

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = {
  x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
};
const mod = (a, m = P) => ((a % m) + m) % m;
function inv(a, m = P) {
  let [lm, hm, low, high] = [1n, 0n, mod(a, m), m];
  while (low > 1n) { const r = high / low; [lm, hm, low, high] = [hm - lm * r, lm, high - low * r, low]; }
  return mod(lm, m);
}
function add(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  if (p1.x === p2.x && mod(p1.y + p2.y) === 0n) return null;
  const l = p1.x === p2.x && p1.y === p2.y
    ? mod(3n * p1.x * p1.x * inv(2n * p1.y))
    : mod((p2.y - p1.y) * inv(p2.x - p1.x));
  const x = mod(l * l - p1.x - p2.x);
  return { x, y: mod(l * (p1.x - x) - p1.y) };
}
function mul(k, pt = G) {
  k = mod(k, N); let r = null, a = pt;
  while (k > 0n) { if (k & 1n) r = add(r, a); a = add(a, a); k >>= 1n; }
  return r;
}
const toHex32 = (v) => v.toString(16).padStart(64, "0");
function encode(pt, compressed = true) {
  if (compressed) return Buffer.from((pt.y & 1n ? "03" : "02") + toHex32(pt.x), "hex");
  return Buffer.from("04" + toHex32(pt.x) + toHex32(pt.y), "hex");
}
function decode(buf) {
  buf = Buffer.from(buf);
  if (buf[0] === 4) return { x: BigInt("0x" + buf.subarray(1, 33).toString("hex")), y: BigInt("0x" + buf.subarray(33, 65).toString("hex")) };
  const x = BigInt("0x" + buf.subarray(1, 33).toString("hex"));
  const y2 = mod(x ** 3n + 7n);
  let y = modPow(y2, (P + 1n) / 4n);
  if ((y & 1n) !== BigInt(buf[0] & 1)) y = P - y;
  return { x, y };
}
function modPow(b, e, m = P) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
const scalar = (buf) => mod(BigInt("0x" + Buffer.from(buf).toString("hex")), N);
function addressOf(pt) {
  const pub = encode(pt, false).subarray(1);
  return "0x" + keccak256(pub).subarray(12).toString("hex");
}
/** EIP-55 checksum address */
function checksum(addr) {
  const a = addr.toLowerCase().replace(/^0x/, "");
  const h = keccak256(Buffer.from(a, "utf8")).toString("hex");
  return "0x" + [...a].map((c, i) => (parseInt(h[i], 16) >= 8 ? c.toUpperCase() : c)).join("");
}

module.exports = { P, N, G, mod, add, mul, encode, decode, scalar, addressOf, checksum };
