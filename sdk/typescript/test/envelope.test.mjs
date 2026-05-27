// Canonical-encoding tests for @stele/sdk.
//
// CRITICAL: for the same inputs, these bytes must be byte-identical
// to what the Go side produces and what the Python SDK produces.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  canonicalBytes,
  envelopeHash,
  envelopeToWire,
  TYPE_SOFTWARE,
} from "../dist/esm/envelope.js";

const enc = new TextEncoder();

test("canonical layout matches the Go byte-by-byte spec", () => {
  const pid = "alice";
  const src = "/var/log/x";
  const data = enc.encode("hello");
  const pub = new Uint8Array(32).fill(0x01);
  const typ = "software";

  const got = canonicalBytes({
    producerId: pid,
    timeNanos: 1700000000123456789n,
    source: src,
    data,
    publicKey: pub,
    attestationType: typ,
  });

  // Hand-roll the expected layout.
  const want = [];
  function pushBytes(bytes) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, bytes.length, false);
    want.push(...len, ...bytes);
  }
  pushBytes(enc.encode(pid));
  // i64 timeNanos
  const t = new Uint8Array(8);
  new DataView(t.buffer).setBigInt64(0, 1700000000123456789n, false);
  want.push(...t);
  pushBytes(enc.encode(src));
  pushBytes(data);
  pushBytes(pub);
  pushBytes(enc.encode(typ));
  pushBytes(new Uint8Array()); // evidenceHash
  pushBytes(new Uint8Array()); // quantumPublicKey

  assert.deepEqual([...got], want);
});

test("zero-length data is still framed", () => {
  const b = canonicalBytes({
    producerId: "x",
    timeNanos: 0n,
    source: "",
    data: new Uint8Array(),
    publicKey: new Uint8Array(32),
  });
  // u32(1) + "x" + i64(0) + u32(0) + u32(0) + u32(32) + 32 zero bytes + u32(8) + "software" + u32(0) + u32(0)
  const expectedLen = 4 + 1 + 8 + 4 + 0 + 4 + 0 + 4 + 32 + 4 + 8 + 4 + 4;
  assert.equal(b.length, expectedLen);
});

test("unicode strings are UTF-8 encoded", () => {
  const b = canonicalBytes({
    producerId: "ñame-é",
    timeNanos: 0n,
    source: "lögs",
    data: new Uint8Array(),
    publicKey: new Uint8Array(32),
  });
  // First u32 should be the UTF-8 length of "ñame-é" = 8.
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  assert.equal(dv.getUint32(0, false), 8);
  assert.deepEqual([...b.slice(4, 12)], [...enc.encode("ñame-é")]);
});

test("quantum_public_key zero-length is still emitted as u32(0)", () => {
  const classical = canonicalBytes({
    producerId: "x",
    timeNanos: 0n,
    source: "",
    data: new Uint8Array(),
    publicKey: new Uint8Array(32),
  });
  const dv = new DataView(
    classical.buffer,
    classical.byteOffset,
    classical.byteLength,
  );
  // Last 4 bytes encode u32(0).
  assert.equal(dv.getUint32(classical.length - 4, false), 0);
});

test("envelopeHash is SHA-256 of canonical", async () => {
  const canonical = canonicalBytes({
    producerId: "alice",
    timeNanos: 1700000000000000000n,
    source: "src",
    data: enc.encode("data"),
    publicKey: new Uint8Array(32).fill(1),
  });

  const env = {
    producerId: "alice",
    timeNanos: 1700000000000000000n,
    source: "src",
    data: enc.encode("data"),
    publicKey: new Uint8Array(32).fill(1),
    attestationType: TYPE_SOFTWARE,
  };
  const hash = await envelopeHash(env);
  assert.equal(hash.length, 32);

  // Independent SHA-256 with WebCrypto.
  const crypto = globalThis.crypto;
  const direct = new Uint8Array(
    await crypto.subtle.digest("SHA-256", canonical),
  );
  assert.deepEqual([...hash], [...direct]);
});

test("envelopeToWire requires a signature", () => {
  assert.throws(
    () =>
      envelopeToWire({
        producerId: "x",
        timeNanos: 0n,
        source: "",
        data: new Uint8Array(),
        publicKey: new Uint8Array(32),
        attestationType: "software",
      }),
    /signature missing/,
  );
});

test("envelopeToWire emits the correct JSON tags", () => {
  const env = {
    producerId: "alice",
    timeNanos: 1700000000000000000n,
    source: "src",
    data: enc.encode("data"),
    publicKey: new Uint8Array(32).fill(1),
    attestationType: TYPE_SOFTWARE,
    signature: new Uint8Array(64).fill(2),
  };
  const w = envelopeToWire(env);
  assert.equal(w.producer_id, "alice");
  assert.equal(w.time_ns, 1700000000000000000);
  assert.equal(w.source, "src");
  assert.equal(w.attestation_type, "software");
  assert.equal(typeof w.data, "string");
  assert.equal(typeof w.public_key, "string");
  assert.equal(typeof w.signature, "string");
});
