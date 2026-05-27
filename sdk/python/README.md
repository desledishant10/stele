# stele-sdk (Python)

The Python producer SDK for [stele](https://github.com/desledishant10/stele).

## Install

```sh
pip install stele-sdk
```

Requires Python 3.9+ and the [`cryptography`](https://cryptography.io)
library (auto-installed as a dependency).

## Usage

```python
from stele import Producer, generate_key

# One-time: generate a producer key and persist it.
priv = generate_key()
priv.to_file("alice.priv")  # 0600 perms on POSIX

# In your service:
priv = PrivateKey.from_file("alice.priv")
producer = Producer(
    id="alice@my-service",
    private_key=priv,
    server="https://stele.example.com",
)

# One-time: enroll via the proof-of-possession ceremony.
producer.enroll(scope="logs:my-service", validity_seconds=86400 * 90)

# Log entries.
resp = producer.log(source="/var/log/app", data=b"user X did Y")
print(resp["entry"]["index"])
```

## Cross-language guarantee

This SDK produces envelope canonical bytes that are **byte-identical**
to what the Go reference implementation produces. We test this with
real Go-server interop tests on every CI run; see
`tests/test_interop.py`. If any byte ever diverges, every signature
this SDK produces would be rejected by the operator — so the test
catches drift loudly.

## API surface

### `stele.Producer`

| Method | Purpose |
|---|---|
| `Producer(id, private_key, server, attestation_type=, ssl_context=, timeout=)` | Construct |
| `enroll(scope=, description=, validity_seconds=)` | Two-step proof-of-possession enrollment |
| `log(source, data, honeypot=)` | Sign + submit one envelope |
| `server_pubkey()` | Fetch the operator's root pubkey (for the auditor's trust anchor) |
| `size()` | Operator's current log size |

### `stele.PrivateKey`

| Method | Purpose |
|---|---|
| `PrivateKey.generate()` / `generate_key()` | Fresh Ed25519 keypair |
| `PrivateKey.from_bytes(b)` | Load from 32-byte seed OR 64-byte Go form |
| `PrivateKey.from_file(path)` | Load from a file written by the Go CLI or by `to_file` |
| `PrivateKey.from_b64(s)` | Load from a base64 string |
| `priv.public_bytes()` / `priv.public_b64()` | Get the public half |
| `priv.seed_bytes()` / `priv.to_bytes()` / `priv.to_b64()` | Serialise |
| `priv.to_file(path)` | Persist with 0600 perms |
| `priv.sign(msg)` | Raw Ed25519 sign |

### `stele.envelope`

Low-level: `canonical_bytes(...)`, `new_envelope(...)`,
`envelope_to_json(env)`. Most callers don't need these — use
`Producer.log()` instead.

### `stele.SteleClient`

Bare HTTP wrapper exposed for callers who want to talk to other
stele endpoints (`/api/v0/checkpoint`, `/api/v0/keychain`, etc.)
without going through the producer surface.

## Running the tests

```sh
cd sdk/python
python -m venv .venv && source .venv/bin/activate
pip install -e '.[test]'

# Unit tests only:
pytest -q tests/test_envelope.py tests/test_keys.py

# Full suite including cross-language interop (needs Go binaries built):
cd ../..
make build
cd sdk/python
pytest -q
```

## License

Apache 2.0 — same as the parent project. See [LICENSE](../../LICENSE).
