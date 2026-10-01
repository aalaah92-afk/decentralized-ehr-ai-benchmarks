"use strict";
/**
 * Off-chain cryptographic protocol of the manuscript (Section 3.4), Node.js built-in crypto only.
 *
 *   P                 plaintext payload (serialized DICOM byte stream)
 *   H_P  = SHA-256(P)                              image-identity commitment
 *   K    <- CSPRNG 256 bit, fresh for EVERY record version
 *   IV   <- CSPRNG 96 bit (crypto.randomBytes), fresh for every encryption
 *   (C, T) = AES-256-GCM_K(IV, P)                  16-byte tag T
 *   bundle = C || IV || T                          object stored on IPFS -> CID
 *   H_C  = SHA-256(C || IV || T || CID)            ciphertext-package integrity digest
 *   signature = ECDSA/secp256k1 over EIP-712 RecordAttestation
 *               (patient, recordId, version, CID, H_P, H_C, timestamp) — see test/helpers.js
 *
 * ECIES key wrapping (secp256k1):
 *   r <-R Z_q*, R = r*G (33-byte compressed)
 *   S_x = x( r * PK_clinician )                    ECDH
 *   K_wrap = HKDF-SHA256(ikm=S_x, salt=R, info="EHR-Key-Wrap", L=16 bytes)
 *   (C_key, T_key) = AES-128-GCM_{K_wrap}(IV_wrap, K, AAD = recordId || version || clinicianAddress)
 *   WK = R || IV_wrap || C_key || T_key            33 + 12 + 32 + 16 = 93 bytes
 * GCM already authenticates the wrapped key, so no separate MAC key is derived.
 */
const crypto = require("crypto");

const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const WRAP_KEY_BYTES = 16;
const WRAPPED_KEY_LENGTH = 33 + GCM_IV_BYTES + AES_KEY_BYTES + GCM_TAG_BYTES; // 93
const HKDF_INFO = Buffer.from("EHR-Key-Wrap", "utf8");

const toBuf = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(String(x).replace(/^0x/, ""), "hex"));
const sha256 = (...parts) => crypto.createHash("sha256").update(Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))))).digest();
const hex32 = (buf) => "0x" + buf.toString("hex");

// ------------------------------------------------------------------ payload encryption
function generateRecordKey() {
  return crypto.randomBytes(AES_KEY_BYTES);
}

function encryptPayload(plaintext, key = generateRecordKey()) {
  if (key.length !== AES_KEY_BYTES) throw new Error("AES-256 key must be 32 bytes");
  const iv = crypto.randomBytes(GCM_IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: GCM_TAG_BYTES });
  const C = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const T = cipher.getAuthTag();
  return { key, iv, C, T, bundle: Buffer.concat([C, iv, T]), payloadDigest: sha256(plaintext) };
}

function splitBundle(bundle) {
  if (bundle.length < GCM_IV_BYTES + GCM_TAG_BYTES) throw new Error("bundle too short");
  const C = bundle.subarray(0, bundle.length - GCM_IV_BYTES - GCM_TAG_BYTES);
  const iv = bundle.subarray(bundle.length - GCM_IV_BYTES - GCM_TAG_BYTES, bundle.length - GCM_TAG_BYTES);
  const T = bundle.subarray(bundle.length - GCM_TAG_BYTES);
  return { C, iv, T };
}

/** Throws if the GCM tag does not authenticate (wrong key or modified C/IV/T). */
function decryptBundle(bundle, key) {
  const { C, iv, T } = splitBundle(bundle);
  const d = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: GCM_TAG_BYTES });
  d.setAuthTag(T);
  return Buffer.concat([d.update(C), d.final()]);
}

/** H_C = SHA-256(C || IV || T || CID) — the bundle already is C||IV||T. */
function ciphertextDigest(bundle, cid) {
  return sha256(bundle, Buffer.from(cid, "utf8"));
}

// ------------------------------------------------------------------ CID (IPFS-compatible)
const B32 = "abcdefghijklmnopqrstuvwxyz234567";
function base32(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
/** CIDv1, raw codec (0x55), sha2-256 multihash, base32 multibase ("b..."). */
function cidV1Raw(bytes) {
  return "b" + base32(Buffer.concat([Buffer.from([0x01, 0x55, 0x12, 0x20]), sha256(bytes)]));
}

// ------------------------------------------------------------------ ECIES key wrapping
function wrapAad(recordId, version, clinicianAddress) {
  const v = Buffer.alloc(8); v.writeBigUInt64BE(BigInt(version));
  return Buffer.concat([toBuf(recordId), v, toBuf(clinicianAddress)]);
}

/**
 * @param K                 32-byte record key
 * @param clinicianPubKey   secp256k1 public key (hex, 0x04.. uncompressed or 0x02/03 compressed)
 * The caller MUST first check that the public key belongs to the clinician's address
 * (address == keccak256(pubkey)[12:]) — see test/helpers.js::assertKeyBinding.
 */
function wrapKey(K, clinicianPubKey, { recordId, version, clinicianAddress }) {
  const eph = crypto.createECDH("secp256k1");
  eph.generateKeys();
  const R = eph.getPublicKey(null, "compressed");
  const Sx = eph.computeSecret(toBuf(clinicianPubKey)); // x-coordinate of r*PK
  const kWrap = Buffer.from(crypto.hkdfSync("sha256", Sx, R, HKDF_INFO, WRAP_KEY_BYTES));
  const ivWrap = crypto.randomBytes(GCM_IV_BYTES);
  const c = crypto.createCipheriv("aes-128-gcm", kWrap, ivWrap, { authTagLength: GCM_TAG_BYTES });
  c.setAAD(wrapAad(recordId, version, clinicianAddress));
  const Ckey = Buffer.concat([c.update(K), c.final()]);
  const wk = Buffer.concat([R, ivWrap, Ckey, c.getAuthTag()]);
  if (wk.length !== WRAPPED_KEY_LENGTH) throw new Error("unexpected wrapped key length");
  return wk;
}

function unwrapKey(wrappedKey, clinicianPrivKey, { recordId, version, clinicianAddress }) {
  const wk = toBuf(wrappedKey);
  if (wk.length !== WRAPPED_KEY_LENGTH) throw new Error("wrapped key must be 93 bytes");
  const R = wk.subarray(0, 33), ivWrap = wk.subarray(33, 45), Ckey = wk.subarray(45, 77), Tkey = wk.subarray(77);
  const ecdh = crypto.createECDH("secp256k1");
  ecdh.setPrivateKey(toBuf(clinicianPrivKey));
  const Sx = ecdh.computeSecret(R);
  const kWrap = Buffer.from(crypto.hkdfSync("sha256", Sx, R, HKDF_INFO, WRAP_KEY_BYTES));
  const d = crypto.createDecipheriv("aes-128-gcm", kWrap, ivWrap, { authTagLength: GCM_TAG_BYTES });
  d.setAAD(wrapAad(recordId, version, clinicianAddress));
  d.setAuthTag(Tkey);
  return Buffer.concat([d.update(Ckey), d.final()]);
}

// ------------------------------------------------------------------ AI inference object
/**
 * Encrypted inference object + commitment Hash_infer = SHA-256(Vector_AI || Salt).
 * Vector_AI is serialized as 14 IEEE-754 float32 big-endian values.
 */
function buildInferenceObject(probabilities, key = generateRecordKey()) {
  if (probabilities.length !== 14) throw new Error("expected 14 pathology probabilities");
  const vec = Buffer.alloc(14 * 4);
  probabilities.forEach((p, i) => vec.writeFloatBE(p, i * 4));
  const salt = crypto.randomBytes(32);
  const commitment = sha256(vec, salt);
  const enc = encryptPayload(Buffer.concat([vec, salt]), key);
  return { vec, salt, commitment, ...enc };
}

function openInferenceObject(bundle, key) {
  const plain = decryptBundle(bundle, key);
  const vec = plain.subarray(0, 56), salt = plain.subarray(56);
  const probabilities = Array.from({ length: 14 }, (_, i) => vec.readFloatBE(i * 4));
  return { probabilities, commitment: sha256(vec, salt) };
}

module.exports = {
  AES_KEY_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES, WRAPPED_KEY_LENGTH,
  sha256, hex32, toBuf, generateRecordKey, encryptPayload, splitBundle, decryptBundle,
  ciphertextDigest, cidV1Raw, wrapKey, unwrapKey, buildInferenceObject, openInferenceObject,
};
