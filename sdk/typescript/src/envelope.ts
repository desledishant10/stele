// Envelope canonical encoding — mirrors pkg/attest/attest.go: Envelope.Canonical().
//
// The CRITICAL property: for the same inputs, the bytes here are
// byte-identical to what the Go side produces. If you change the
// layout, every signature this SDK produces will fail to verify.
//
// Wire format:
//   u32 len(ProducerID)        || ProducerID
//   i64 TimeNanos              (big-endian, signed)
//   u32 len(Source)            || Source
//   u32 len(Data)              || Data
//   u32 len(PublicKey)         || PublicKey
//   u32 len(AttestationType)   || AttestationType
//   u32 len(EvidenceHash)      || EvidenceHash
//   u32 len(QuantumPublicKey)  || QuantumPublicKey   (zero-length classical mode)

export const TYPE_SOFTWARE = "software";

/** A producer-signed envelope ready to POST to /api/v0/append. */
export interface Envelope {
  producerId: string;
  timeNanos: bigint;
  source: string;
  data: Uint8Array;
  publicKey: Uint8Array;
  attestationType: string;
  evidenceHash?: Uint8Array;
  evidence?: Uint8Array;
  signature?: Uint8Array;
  quantumPublicKey?: Uint8Array;
  quantumSignature?: Uint8Array;
}

/** Inputs to canonicalBytes — exactly the fields covered by the signature. */
export interface CanonicalInputs {
  producerId: string;
  timeNanos: bigint;
  source: string;
  data: Uint8Array;
  publicKey: Uint8Array;
  attestationType?: string;
  evidenceHash?: Uint8Array;
  quantumPublicKey?: Uint8Array;
}

/** Pure function: produce the canonical bytes for the given envelope fields. */
export function canonicalBytes(inp: CanonicalInputs): Uint8Array {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];

  parts.push(putBytes(enc.encode(inp.producerId)));
  parts.push(putInt64BE(inp.timeNanos));
  parts.push(putBytes(enc.encode(inp.source)));
  parts.push(putBytes(inp.data));
  parts.push(putBytes(inp.publicKey));
  parts.push(putBytes(enc.encode(inp.attestationType ?? TYPE_SOFTWARE)));
  parts.push(putBytes(inp.evidenceHash ?? new Uint8Array()));
  parts.push(putBytes(inp.quantumPublicKey ?? new Uint8Array()));

  return concat(parts);
}

/** SHA-256 of the canonical bytes — used by the operator's replay-protection table. */
export async function envelopeHash(env: Envelope): Promise<Uint8Array> {
  const canonical = canonicalBytes({
    producerId: env.producerId,
    timeNanos: env.timeNanos,
    source: env.source,
    data: env.data,
    publicKey: env.publicKey,
    attestationType: env.attestationType,
    evidenceHash: env.evidenceHash,
    quantumPublicKey: env.quantumPublicKey,
  });
  const buf = await getCrypto().subtle.digest(
    "SHA-256",
    canonical as unknown as BufferSource,
  );
  return new Uint8Array(buf);
}

/** Serialise an envelope to a JSON-friendly object matching the Go struct tags. */
export function envelopeToWire(env: Envelope): Record<string, unknown> {
  if (!env.signature || env.signature.length === 0) {
    throw new Error("envelopeToWire: signature missing — call signEnvelope first");
  }
  const out: Record<string, unknown> = {
    producer_id: env.producerId,
    time_ns: Number(env.timeNanos),
    source: env.source,
    data: b64(env.data),
    public_key: b64(env.publicKey),
    attestation_type: env.attestationType,
    signature: b64(env.signature),
  };
  if (env.evidenceHash && env.evidenceHash.length > 0) {
    out.evidence_hash = b64(env.evidenceHash);
  }
  if (env.evidence && env.evidence.length > 0) {
    out.evidence = b64(env.evidence);
  }
  if (env.quantumPublicKey && env.quantumPublicKey.length > 0) {
    out.quantum_public_key = b64(env.quantumPublicKey);
  }
  if (env.quantumSignature && env.quantumSignature.length > 0) {
    out.quantum_signature = b64(env.quantumSignature);
  }
  return out;
}

// ---- helpers ----

function putBytes(b: Uint8Array): Uint8Array {
  const len = new ArrayBuffer(4);
  new DataView(len).setUint32(0, b.length, false); // big-endian
  const out = new Uint8Array(4 + b.length);
  out.set(new Uint8Array(len), 0);
  out.set(b, 4);
  return out;
}

function putInt64BE(n: bigint): Uint8Array {
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigInt64(0, n, false); // big-endian
  return new Uint8Array(buf);
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Base64-encode with no line wrapping, no padding stripping. */
export function b64(b: Uint8Array): string {
  // Node and modern browsers both expose btoa/atob OR Buffer; we
  // pick the route that exists.
  if (typeof Buffer !== "undefined") {
    return Buffer.from(b).toString("base64");
  }
  let s = "";
  for (let i = 0; i < b.length; i++) {
    s += String.fromCharCode(b[i]!);
  }
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
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

/** Get the WebCrypto SubtleCrypto in both Node ≥18 and browsers. */
export function getCrypto(): Crypto {
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  // Older Node fallback path.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return require("node:crypto").webcrypto as Crypto;
}
