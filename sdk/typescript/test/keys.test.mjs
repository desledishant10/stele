// Ed25519 key tests.

import { test } from "node:test";
import assert from "node:assert/strict";

import { PrivateKey, generateKey, verify } from "../dist/esm/keys.js";

const enc = new TextEncoder();

test("generate + sign + verify roundtrip", async () => {
  const priv = await generateKey();
  const msg = enc.encode("hello stele");
  const sig = await priv.sign(msg);
  assert.equal(sig.length, 64);
  assert.equal(await verify(priv.publicBytes(), msg, sig), true);
});

test("publicBytes is 32 bytes", async () => {
  const priv = await generateKey();
  assert.equal(priv.publicBytes().length, 32);
});

test("verify rejects bit-flipped signature", async () => {
  const priv = await generateKey();
  const msg = enc.encode("hello");
  const sig = await priv.sign(msg);
  sig[0] ^= 0xff;
  assert.equal(await verify(priv.publicBytes(), msg, sig), false);
});

test("verify rejects wrong message", async () => {
  const priv = await generateKey();
  const sig = await priv.sign(enc.encode("hello"));
  assert.equal(
    await verify(priv.publicBytes(), enc.encode("world"), sig),
    false,
  );
});

test("verify rejects wrong public key", async () => {
  const a = await generateKey();
  const b = await generateKey();
  const sig = await a.sign(enc.encode("hello"));
  assert.equal(await verify(b.publicBytes(), enc.encode("hello"), sig), false);
});
