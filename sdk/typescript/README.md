# @stele/sdk (TypeScript)

The TypeScript / JavaScript producer SDK for
[stele](https://github.com/desledishant10/stele). Runs in Node ≥18 and
modern browsers via WebCrypto.

## Install

```sh
npm install @stele/sdk
# or pnpm add @stele/sdk / yarn add @stele/sdk
```

Zero runtime dependencies. WebCrypto + `fetch` are used directly from
the host environment.

## Usage

```ts
import { Producer, generateKey, PrivateKey } from "@stele/sdk";

// One-time: generate a producer key and persist it.
const priv = await generateKey();
// In Node:
import { writeFile } from "node:fs/promises";
await writeFile("alice.priv", new Uint8Array(priv.publicBytes()));
// (For now persist the seed yourself; a PrivateKey.toFile() helper
// is planned. The Python SDK has one already.)

// In your service:
const producer = new Producer({
  id: "alice@my-service",
  privateKey: priv,
  server: "https://stele.example.com",
});

// One-time: enroll via the proof-of-possession ceremony.
await producer.enroll({
  scope: "logs:my-service",
  validitySeconds: 86400 * 90,
});

// Log entries.
const resp = await producer.log({
  source: "/var/log/app",
  data: "user X did Y", // strings auto-encoded as UTF-8
});
console.log(resp.entry.index);
```

## Browser support

The SDK works in the browser unchanged — WebCrypto's Ed25519 support
landed broadly in 2024. Bundlers that tree-shake will drop the
node-specific Buffer fallback automatically.

```html
<script type="module">
  import { Producer, generateKey } from "https://esm.sh/@stele/sdk";
  const priv = await generateKey();
  // ...
</script>
```

## Cross-language guarantee

This SDK produces envelope canonical bytes that are **byte-identical**
to what the Go reference implementation produces AND what the
Python SDK produces. We test this with real Go-server interop tests
on every CI run; see `test/interop.test.mjs`. If any byte ever
diverges, every signature this SDK produces would be rejected by the
operator — so the test catches drift loudly.

## API surface

### `Producer`

```ts
new Producer({
  id: string,
  privateKey: PrivateKey,
  server: string,
  attestationType?: string,    // default "software"
  timeoutMs?: number,           // default 15000
  fetchImpl?: typeof fetch,     // for tests / custom transport
});

producer.enroll({ scope?, description?, validitySeconds? }): Promise<unknown>;
producer.log({ source, data, honeypot? }): Promise<unknown>;
producer.serverPubkey(): Promise<Uint8Array>;
producer.size(): Promise<number>;
```

### `PrivateKey`

```ts
PrivateKey.generate(): Promise<PrivateKey>;
PrivateKey.fromBytes(b: Uint8Array): Promise<PrivateKey>;    // accepts 32 or 64 bytes
PrivateKey.fromBase64(s: string): Promise<PrivateKey>;
priv.publicBytes(): Uint8Array;                              // 32 bytes
priv.sign(msg: Uint8Array): Promise<Uint8Array>;             // 64-byte sig
verify(pub, msg, sig): Promise<boolean>;                     // standalone verify
```

### Low-level envelope helpers

```ts
import { canonicalBytes, envelopeHash, envelopeToWire } from "@stele/sdk";

const bytes = canonicalBytes({
  producerId: "alice",
  timeNanos: BigInt(Date.now()) * 1_000_000n,
  source: "src",
  data: new TextEncoder().encode("hello"),
  publicKey: priv.publicBytes(),
});
const sig = await priv.sign(bytes);
```

Most callers use `producer.log()` and never touch these — they're
exposed for callers who want to do producer-side work (build
envelopes, queue them, batch them) before submission.

## Running the tests

```sh
cd sdk/typescript
npm install
npm run build

# Unit tests only:
node --test test/envelope.test.mjs test/keys.test.mjs

# Full suite including cross-language interop (needs Go binaries built):
cd ../..
make build
cd sdk/typescript
npm test
```

## License

Apache 2.0 — same as the parent project. See [LICENSE](../../LICENSE).
