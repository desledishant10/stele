/**
 * Producer SDK for the stele provenance-anchored audit log.
 *
 * Quickstart:
 *
 * ```ts
 * import { Producer, generateKey } from "@stele/sdk";
 *
 * const priv = await generateKey();
 * const producer = new Producer({
 *   id: "alice",
 *   privateKey: priv,
 *   server: "https://stele.example.com",
 * });
 *
 * await producer.enroll({ scope: "logs:audit", validitySeconds: 86400 * 90 });
 * await producer.log({ source: "my.app", data: "first entry" });
 * ```
 */

export { Producer } from "./producer.js";
export type {
  ProducerOptions,
  EnrollOptions,
  LogOptions,
} from "./producer.js";
export { PrivateKey, generateKey, verify } from "./keys.js";
export {
  TYPE_SOFTWARE,
  canonicalBytes,
  envelopeHash,
  envelopeToWire,
  b64,
  b64decode,
} from "./envelope.js";
export type { Envelope, CanonicalInputs } from "./envelope.js";
export { SteleClient, HTTPError } from "./client.js";
export type { SteleClientOptions } from "./client.js";
