// High-level Producer class — wraps PrivateKey + SteleClient so the
// caller does `await producer.log({...})` and `await producer.enroll({...})`
// without touching envelope canonicalisation or HTTP details.

import {
  Envelope,
  TYPE_SOFTWARE,
  b64,
  b64decode,
  canonicalBytes,
  envelopeToWire,
} from "./envelope.js";
import { SteleClient, SteleClientOptions } from "./client.js";
import { PrivateKey } from "./keys.js";

export interface ProducerOptions {
  id: string;
  privateKey: PrivateKey;
  server: string;
  attestationType?: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export interface EnrollOptions {
  scope?: string;
  description?: string;
  validitySeconds?: number;
}

export interface LogOptions {
  source: string;
  data: Uint8Array | string;
  honeypot?: boolean;
}

interface BeginResponse {
  challenge_id: string;
  challenge_bytes: string; // base64
  expires_at_ns: number;
}

export class Producer {
  readonly id: string;
  readonly privateKey: PrivateKey;
  readonly attestationType: string;
  readonly client: SteleClient;

  constructor(opts: ProducerOptions) {
    if (!opts.id) throw new Error("Producer: id required");
    if (!opts.privateKey) throw new Error("Producer: privateKey required");
    this.id = opts.id;
    this.privateKey = opts.privateKey;
    this.attestationType = opts.attestationType ?? TYPE_SOFTWARE;
    this.client = new SteleClient({
      baseUrl: opts.server,
      timeoutMs: opts.timeoutMs,
      fetchImpl: opts.fetchImpl,
    } satisfies SteleClientOptions);
  }

  /** Two-step proof-of-possession enrollment ceremony. */
  async enroll(opts: EnrollOptions = {}): Promise<unknown> {
    const beginReq: Record<string, unknown> = {
      id: this.id,
      public_key: b64(this.privateKey.publicBytes()),
      attestation_type: this.attestationType,
    };
    if (opts.scope) beginReq.scope = opts.scope;
    if (opts.description) beginReq.description = opts.description;
    if (opts.validitySeconds && opts.validitySeconds > 0) {
      beginReq.validity_seconds = opts.validitySeconds;
    }

    const begin = await this.client.post<BeginResponse>(
      "/api/v0/enrollments/begin",
      beginReq,
    );
    const challenge = b64decode(begin.challenge_bytes);
    const signature = await this.privateKey.sign(challenge);

    return this.client.post("/api/v0/enrollments/confirm", {
      challenge_id: begin.challenge_id,
      signature: b64(signature),
    });
  }

  /** Sign + submit one envelope; return the operator's response. */
  async log(opts: LogOptions): Promise<unknown> {
    const data =
      typeof opts.data === "string" ? new TextEncoder().encode(opts.data) : opts.data;

    const env: Envelope = {
      producerId: this.id,
      timeNanos: BigInt(Date.now()) * 1_000_000n,
      source: opts.source,
      data,
      publicKey: this.privateKey.publicBytes(),
      attestationType: this.attestationType,
    };

    const canonical = canonicalBytes({
      producerId: env.producerId,
      timeNanos: env.timeNanos,
      source: env.source,
      data: env.data,
      publicKey: env.publicKey,
      attestationType: env.attestationType,
    });
    env.signature = await this.privateKey.sign(canonical);

    return this.client.post("/api/v0/append", {
      envelope: envelopeToWire(env),
      honeypot: opts.honeypot ?? false,
    });
  }

  /** Fetch the operator's root pubkey (auditor trust anchor). */
  async serverPubkey(): Promise<Uint8Array> {
    const resp = await this.client.get<{ root_public_key: string }>(
      "/api/v0/pubkey",
    );
    return b64decode(resp.root_public_key);
  }

  /** Current size of the operator's log. */
  async size(): Promise<number> {
    const resp = await this.client.get<{ size: number }>("/api/v0/size");
    return resp.size;
  }
}
