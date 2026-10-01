"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { keccak256 } = require("../lib/keccak");
const E = require("../lib/secp256k1");

test("keccak256 known-answer vectors", () => {
  assert.equal(keccak256(Buffer.alloc(0)).toString("hex"), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(keccak256(Buffer.from("abc")).toString("hex"), "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
});

test("secp256k1: private key 1 -> 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf (EIP-55)", () => {
  assert.equal(E.checksum(E.addressOf(E.mul(1n))), "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
});

test("secp256k1 scalar multiplication matches OpenSSL on 50 random keys", () => {
  for (let i = 0; i < 50; i++) {
    const e = crypto.createECDH("secp256k1"); e.generateKeys();
    const pt = E.mul(E.scalar(e.getPrivateKey()));
    assert.ok(E.encode(pt).equals(e.getPublicKey(null, "compressed")));
    assert.ok(E.encode(pt, false).equals(e.getPublicKey()));
    assert.deepEqual(E.decode(E.encode(pt)), pt);
  }
});
