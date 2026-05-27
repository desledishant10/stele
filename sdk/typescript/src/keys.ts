// Ed25519 keypair handling for stele producers.
//
// Strategy: WebCrypto's Ed25519 support landed broadly in Node 18+
// AND every modern browser, but its raw-key import format is the
// classic "Algorithm.name: 'Ed25519'" + Uint8Array seed flow. We
// wrap that so the rest of the SDK never touches CryptoKey directly.

import { getCrypto } from "./envelope.js";

const ALGORITHM: EcKeyAlgorithm = { name: "Ed25519" } as EcKeyAlgorithm;

export class PrivateKey {
  private readonly key: CryptoKey;
  private readonly pubBytes: Uint8Array;

  private constructor(key: CryptoKey, pub: Uint8Array) {
    this.key = key;
    this.pubBytes = pub;
  }

  /** Generate a fresh Ed25519 keypair. */
  static async generate(): Promise<PrivateKey> {
    const crypto = getCrypto();
    const pair = (await crypto.subtle.generateKey(
      ALGORITHM,
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
    const pubBuf = await crypto.subtle.exportKey("raw", pair.publicKey);
    return new PrivateKey(pair.privateKey, new Uint8Array(pubBuf));
  }

  /** Load from the raw 32-byte seed OR Go's 64-byte (seed || pub) form. */
  static async fromBytes(b: Uint8Array): Promise<PrivateKey> {
    let seed: Uint8Array;
    if (b.length === 64) {
      seed = b.slice(0, 32);
    } else if (b.length === 32) {
      seed = b;
    } else {
      throw new Error(`PrivateKey: expected 32 or 64 bytes, got ${b.length}`);
    }
    const crypto = getCrypto();
    // WebCrypto's raw Ed25519 import takes the 32-byte seed.
    const priv = await crypto.subtle.importKey(
      "raw",
      seed as unknown as BufferSource,
      ALGORITHM,
      true,
      ["sign"],
    );
    // Re-derive the public key by signing the empty string?
    // No — we instead re-import as a PKCS8 pair or use pkcs8 path.
    // Simpler: WebCrypto can't derive Ed25519 pub from seed alone
    // through `importKey('raw', ...)`. Solution: use the standard
    // RFC 8032 derivation by importing as `pkcs8` after wrapping
    // the seed in the standard PKCS#8 envelope.
    const pubKey = await deriveEd25519Public(seed, crypto);
    const pubRaw = await crypto.subtle.exportKey("raw", pubKey);
    return new PrivateKey(priv, new Uint8Array(pubRaw));
  }

  /** Load from a base64-encoded key (matches the Go CLI's `producer-init --out` format). */
  static async fromBase64(s: string): Promise<PrivateKey> {
    const bin = atobUniversal(s.trim());
    return PrivateKey.fromBytes(bin);
  }

  /** Raw 32-byte Ed25519 public key. */
  publicBytes(): Uint8Array {
    return this.pubBytes;
  }

  /** Sign a message; returns the 64-byte Ed25519 signature. */
  async sign(msg: Uint8Array): Promise<Uint8Array> {
    const sigBuf = await getCrypto().subtle.sign(
      ALGORITHM,
      this.key,
      msg as unknown as BufferSource,
    );
    return new Uint8Array(sigBuf);
  }
}

/** Top-level: produce a fresh key. Same as PrivateKey.generate(). */
export const generateKey = PrivateKey.generate;

/** Verify a signature with a 32-byte Ed25519 public key — used by tests. */
export async function verify(
  pub: Uint8Array,
  msg: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const crypto = getCrypto();
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      pub as unknown as BufferSource,
      ALGORITHM,
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      ALGORITHM,
      key,
      signature as unknown as BufferSource,
      msg as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

// ---- helpers ----

// PKCS8 prefix for an Ed25519 private key (RFC 8410). The body is
// 0x04 0x20 followed by the 32-byte seed. Wrapping the seed this
// way lets WebCrypto's `importKey('pkcs8', ...)` give us back a
// keypair from which we can extract the public half.
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

async function deriveEd25519Public(
  seed: Uint8Array,
  crypto: Crypto,
): Promise<CryptoKey> {
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  const priv = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as unknown as BufferSource,
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  // Re-export as JWK to grab the public part.
  const jwk = await crypto.subtle.exportKey("jwk", priv);
  if (!jwk.x) {
    throw new Error("PrivateKey: failed to derive public key from seed");
  }
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
    { name: "Ed25519" },
    true,
    ["verify"],
  );
}

function atobUniversal(s: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(s, "base64"));
  }
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}
