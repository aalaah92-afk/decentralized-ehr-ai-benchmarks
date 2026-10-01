"use strict";
/**
 * Off-chain storage adapters.
 *  - LocalCASStore: in-process content-addressed store (IPFS-compatible CIDv1/raw/sha2-256).
 *    Used by the automated tests so they run without an IPFS daemon. It does NOT measure
 *    IPFS network performance.
 *  - KuboStore: real IPFS node via the Kubo HTTP RPC API (set IPFS_API=http://127.0.0.1:5001).
 *    Used by scripts/benchmark-ipfs.js for Table 6 upload/download timings.
 */
const { cidV1Raw } = require("./ehrCrypto");

class LocalCASStore {
  constructor() { this.blobs = new Map(); }
  async add(bytes) { const cid = cidV1Raw(bytes); this.blobs.set(cid, Buffer.from(bytes)); return cid; }
  async cat(cid) { const b = this.blobs.get(cid); if (!b) throw new Error(`CID not found: ${cid}`); return Buffer.from(b); }
  /** Test hook: overwrite the bytes served for a CID (simulates a malicious/corrupted node). */
  tamper(cid, mutate) {
    const original = this.blobs.get(cid);
    this.blobs.set(cid, mutate(Buffer.from(original)));
    return () => this.blobs.set(cid, original); // restore function
  }
}

class KuboStore {
  constructor(api = process.env.IPFS_API || "http://127.0.0.1:5001") { this.api = api.replace(/\/$/, ""); }
  async add(bytes, { pin = true } = {}) {
    const form = new FormData();
    form.append("file", new Blob([bytes]), "bundle.bin");
    const res = await fetch(`${this.api}/api/v0/add?cid-version=1&raw-leaves=true&pin=${pin}`, { method: "POST", body: form });
    if (!res.ok) throw new Error(`ipfs add failed: ${res.status} ${await res.text()}`);
    return JSON.parse((await res.text()).trim().split("\n").pop()).Hash;
  }
  async cat(cid) {
    const res = await fetch(`${this.api}/api/v0/cat?arg=${encodeURIComponent(cid)}`, { method: "POST" });
    if (!res.ok) throw new Error(`ipfs cat failed: ${res.status} ${await res.text()}`);
    return Buffer.from(await res.arrayBuffer());
  }
  async version() {
    const res = await fetch(`${this.api}/api/v0/version`, { method: "POST" });
    return res.ok ? (await res.json()).Version : "unknown";
  }
}

module.exports = { LocalCASStore, KuboStore };
