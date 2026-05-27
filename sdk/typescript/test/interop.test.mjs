// Cross-language interop: TypeScript signs, Go's steled verifies.
//
// Spins up an isolated `steled` process and proves a TS-signed
// envelope is accepted by the Go server. Skipped if the binaries
// aren't built; run `make build` from the repo root first.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";

import { Producer, generateKey, HTTPError } from "../dist/esm/index.js";

const REPO_ROOT = new URL("../../..", import.meta.url).pathname;
const BIN_DIR = process.env.STELE_BIN_DIR ?? `${REPO_ROOT}/bin`;
const STELED = `${BIN_DIR}/steled`;
const STELE = `${BIN_DIR}/stele`;

let steledProc = null;
let baseUrl = null;
let dataDir = null;

async function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitReady(url, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(500) });
      if (r.ok) return;
    } catch {
      /* loop */
    }
    await sleep(100);
  }
  throw new Error(`server at ${url} never became ready within ${timeoutMs}ms`);
}

before(async () => {
  if (!existsSync(STELED) || !existsSync(STELE)) {
    // Mark all tests in this file as skipped by erroring once;
    // node:test will surface this as a failure unless we use t.skip,
    // so we accept the prerequisite or document the gap.
    console.warn(`SKIP: ${STELED} / ${STELE} not found — run \`make build\``);
    return;
  }
  const port = await freePort();
  baseUrl = `http://127.0.0.1:${port}`;
  dataDir = mkdtempSync(join(tmpdir(), "stele-ts-interop-"));
  steledProc = spawn(
    STELED,
    [
      "--addr",
      `:${port}`,
      "--dir",
      dataDir,
      "--origin",
      "interop.local/log",
      "--init",
      "--checkpoint-every",
      "0",
      "--anchor-every",
      "0",
      "--beacon",
      "",
      "--rotate-every",
      "0",
      "--watch-keys=false",
      "--watch-rate=false",
      "--read-log=false",
      "--tripwire-every",
      "0",
    ],
    {
      env: { ...process.env, STELE_LOG_LEVEL: "warn", STELE_LOG_FORMAT: "json" },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  await waitReady(`${baseUrl}/readyz`);
});

after(async () => {
  if (steledProc) {
    steledProc.kill("SIGTERM");
    await new Promise((resolve) => {
      steledProc.once("close", resolve);
      setTimeout(() => {
        try {
          steledProc.kill("SIGKILL");
        } catch {}
        resolve(undefined);
      }, 5000);
    });
  }
  if (dataDir) {
    try {
      rmSync(dataDir, { recursive: true, force: true });
    } catch {}
  }
});

test("TS-signed envelope is accepted by the Go server", async (t) => {
  if (!baseUrl) {
    t.skip("steled not available");
    return;
  }
  const priv = await generateKey();
  const prod = new Producer({
    id: "ts-interop-prod",
    privateKey: priv,
    server: baseUrl,
  });

  // Two-step proof-of-possession enrollment.
  const confirm = await prod.enroll({
    scope: "logs:interop-test",
    validitySeconds: 3600,
  });
  assert.ok(confirm, "enrollment confirm must return a body");

  // Submit 5 entries; each must succeed.
  const indices = [];
  for (let i = 0; i < 5; i++) {
    const enc = new TextEncoder();
    const resp = await prod.log({
      source: "ts-interop",
      data: enc.encode(`entry ${i}`),
    });
    indices.push(resp.entry.index);
  }
  assert.deepEqual(indices, [0, 1, 2, 3, 4]);

  // Fetch the last entry back and confirm the producer_id round-tripped.
  const last = await prod.client.get(`/api/v0/entries/${indices.at(-1)}`);
  assert.equal(last.entry.envelope.producer_id, "ts-interop-prod");
});

test("operator's replay-protection rejects a duplicated TS envelope", async (t) => {
  if (!baseUrl) {
    t.skip("steled not available");
    return;
  }
  const priv = await generateKey();
  const prod = new Producer({
    id: "ts-replay-prod",
    privateKey: priv,
    server: baseUrl,
  });
  await prod.enroll({ scope: "logs:replay-test" });

  // Build one envelope with a fixed timestamp so the hash is stable,
  // submit twice. Second submit must fail (replay protection).
  const { canonicalBytes, envelopeToWire, b64 } = await import(
    "../dist/esm/envelope.js"
  );

  const env = {
    producerId: "ts-replay-prod",
    timeNanos: 1700000000000000000n,
    source: "replay-test",
    data: new TextEncoder().encode("only once"),
    publicKey: priv.publicBytes(),
    attestationType: "software",
  };
  env.signature = await priv.sign(
    canonicalBytes({
      producerId: env.producerId,
      timeNanos: env.timeNanos,
      source: env.source,
      data: env.data,
      publicKey: env.publicKey,
      attestationType: env.attestationType,
    }),
  );
  const body = { envelope: envelopeToWire(env), honeypot: false };

  const first = await prod.client.post("/api/v0/append", body);
  assert.ok(first.entry, "first submit should succeed");

  await assert.rejects(
    () => prod.client.post("/api/v0/append", body),
    (err) => err instanceof HTTPError,
    "second submit of an identical envelope must be refused by replay protection",
  );
});
