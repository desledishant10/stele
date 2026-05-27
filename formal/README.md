# Formal verification of the stele protocol

This directory contains a [Tamarin](https://tamarin-prover.com/) model
of stele's three core security claims. It produces machine-checked
proofs in the symbolic (Dolev-Yao) model — the same kind of evidence
that landed TLS 1.3 in academic publication.

## What's modeled

| Lemma | Claim | Where in the code |
|---|---|---|
| `forward_secrecy` | A signature attributed to epoch N cannot be retroactively forged after a key from epoch N+k is compromised. The operator's rotation chain destroys past keys irrevocably. | [pkg/fwdsec/keystore.go](../pkg/fwdsec/keystore.go) `Destroy()` |
| `no_witness_double_cosign` | An honest witness cannot cosign two different roots at the same size for the same operator. Cornerstone of fork detection. | [pkg/witness/witness.go](../pkg/witness/witness.go) seen-map check |
| `enrollment_required` | An entry is accepted only when an operator-signed enrollment AND a producer's proof-of-possession exists for that producer ID + pubkey. | [pkg/core/log.go](../pkg/core/log.go) `Append` + [pkg/storage/producers.go](../pkg/storage/producers.go) |
| `sanity_complete_run` | Sanity check: at least one trace exists where an honest run completes — confirms the lemmas above are not vacuously true. | — |

The two anti-claims are NOT modeled here (left to future work):

- **Replay protection on envelope hash** — needs Tamarin's multiset
  rewriting on the operator's hash table, which we'd model as a
  counting fact. Implementation in [pkg/storage/replay.go](../pkg/storage/replay.go).
- **Threshold (t-of-N)** — requires a non-trivial extension to the
  symbolic-model setup; either a quorum primitive or N parallel
  signature traces.
- **Hybrid PQ** — Dilithium3 has the same EUF-CMA properties as
  Ed25519 in the symbolic model, so a hybrid lemma would be identical
  to the classical one. We rely on the implementation-level
  defence-in-depth + the fact that NIST FIPS 204 inherits EUF-CMA
  from concrete cryptanalysis.

## Running the checker

Tamarin's `tamarin-prover` is the only dependency.

```sh
# macOS:
brew install tamarin-prover

# Linux:
# See https://tamarin-prover.com/manual/master/book/002_installation.html

# Check the model parses (fast):
tamarin-prover stele.spthy

# Run every proof (can take minutes):
tamarin-prover --prove stele.spthy
```

Expected output ([`expected-output.txt`](expected-output.txt)
captures what the maintainers observed at last check):

```
==============================================================================
analyzed: stele.spthy

  forward_secrecy (all-traces): verified
  no_witness_double_cosign (all-traces): verified
  enrollment_required (all-traces): verified
  sanity_complete_run (exists-trace): verified
==============================================================================
```

If any lemma reports `INDETERMINATE`, the bounded search did not
conclude. Re-run with `--heuristic=O` or `--heuristic=I` to try
alternate search strategies; if it still doesn't conclude, the model
likely needs additional helper lemmas. Open an issue with the output
and we'll iterate.

## What the model does NOT cover

Be honest with whoever's reading this:

- **Implementation faithfulness**: this is a SYMBOLIC model. It proves
  that the *protocol* doesn't have certain attacks under a Dolev-Yao
  attacker AND assuming idealised primitives. It does NOT prove
  that the Go code correctly implements the protocol. For
  implementation-level evidence, look at [HARDENING.md](../HARDENING.md)
  (fuzz + property + race + chaos tests).
- **Computational soundness**: Tamarin uses symbolic crypto
  (signatures are ideal, hashes collision-free). The symbolic-to-
  computational reduction for the primitives we use (Ed25519,
  Dilithium3, SHA-256) is established in the cryptographic
  literature — we're not re-proving it here.
- **Timing / side channels / hardware attacks**: out of scope by
  construction in a symbolic model.

In other words: this model is necessary evidence for academic
credibility and adopter trust, but it's not sufficient on its own.
The full case for stele's security is the combination of:

1. This Tamarin model (protocol-level)
2. The fuzz + property + chaos tests (implementation-level)
3. The threat model + audit kit (operational-level)
4. (Pending) A third-party security audit

## Citation

If you use this work in a paper, cite as:

```
@misc{stele-tamarin,
  author = {stele maintainers},
  title  = {Stele: A Tamarin model of the provenance-anchored audit log},
  year   = {2026},
  url    = {https://github.com/desledishant10/stele/tree/main/formal},
}
```

A standalone academic writeup is in [papers/PAPER.md](../papers/PAPER.md).
