"use strict";
/**
 * Stealth addresses for clinician recipients, following the ERC-5564 secp256k1 scheme (scheme id 1).
 *
 *   Clinician publishes a stealth meta-address (P_spend, P_view).
 *   Patient (sender), per access grant:
 *     p_eph <-R Z_n*, P_eph = p_eph*G
 *     S     = p_eph * P_view                 (ECDH point)
 *     s_h   = keccak256(compressed(S))
 *     viewTag = s_h[0]
 *     P_stealth = P_spend + s_h*G  -> stealth address A = keccak256(P_stealth)[12:]
 *   Patient calls grantAccess(recordId, A, ...), wraps K for P_stealth (ECIES), and publishes
 *   (P_eph, viewTag) as announcement metadata.
 *   Clinician scans announcements: S = p_view*P_eph, checks viewTag, derives
 *     p_stealth = p_spend + s_h (mod n), whose address equals A.
 *
 * Every grant therefore targets a fresh, unlinkable recipient address; only the holder of p_view
 * can recognise it and only the holder of p_spend can use it.
 */
const crypto = require("crypto");
const E = require("./secp256k1");
const { keccak256 } = require("./keccak");

function randomScalar() {
  for (;;) { const k = E.scalar(crypto.randomBytes(32)); if (k !== 0n) return k; }
}

function generateMetaAddress() {
  const spendPriv = randomScalar(), viewPriv = randomScalar();
  return {
    spendPriv, viewPriv,
    meta: { spendPub: E.encode(E.mul(spendPriv)), viewPub: E.encode(E.mul(viewPriv)) },
  };
}

function generateStealthAddress(meta) {
  const ephPriv = randomScalar();
  const ephPub = E.encode(E.mul(ephPriv));
  const S = E.mul(ephPriv, E.decode(meta.viewPub));
  const sh = keccak256(E.encode(S));
  const Pst = E.add(E.decode(meta.spendPub), E.mul(E.scalar(sh)));
  return { stealthAddress: E.checksum(E.addressOf(Pst)), stealthPub: E.encode(Pst, false), ephemeralPub: ephPub, viewTag: sh[0] };
}

/** Returns null if the announcement is not for this clinician; else the stealth private key. */
function checkAndDerive({ ephemeralPub, viewTag, stealthAddress }, viewPriv, spendPriv) {
  const S = E.mul(viewPriv, E.decode(ephemeralPub));
  const sh = keccak256(E.encode(S));
  if (sh[0] !== viewTag) return null;
  const priv = E.mod(spendPriv + E.scalar(sh), E.N);
  if (E.checksum(E.addressOf(E.mul(priv))) !== stealthAddress) return null;
  return Buffer.from(priv.toString(16).padStart(64, "0"), "hex");
}

module.exports = { generateMetaAddress, generateStealthAddress, checkAndDerive, randomScalar };
