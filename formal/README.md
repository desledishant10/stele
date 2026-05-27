# Formal verification of the stele protocol

This directory contains a [Tamarin](https://tamarin-prover.com/) model
of stele's three core security claims, intended to produce machine-
checked proofs in the symbolic (Dolev-Yao) model.

> **Status (v0.1.x): work in progress.** The model parses and Tamarin
> can run all four lemmas, but two of them currently *fail*. See
> [expected-output.txt](expected-output.txt) for the actual results
> and the [Status](#status) section below. We are debugging whether
> this is a model error (most likely) or a real protocol flaw. Issues
> [#4](https://github.com/desledishant10/stele/issues/4) and
> [#5](https://github.com/desledishant10/stele/issues/5) track the
> investigation.

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

### Status

Actual current output of the prover (see
[expected-output.txt](expected-output.txt) for the full transcript):

```
WARNING: 1 wellformedness check failed!
         The analysis results might be wrong!

forward_secrecy          (all-traces):   falsified - found trace (4 steps)
no_witness_double_cosign (all-traces):   falsified - found trace (4 steps)
enrollment_required      (all-traces):   verified (8 steps)
sanity_complete_run      (exists-trace): pending re-run
```

Note that the wellformedness warning reports that `EnrollBegin` and
`AppendEntry` rules leak the producer signing-pubkey `spk` to the
adversary, which is more permissive than the protocol actually is.
That permissiveness is almost certainly why the two failing lemmas
fail — fixing the wellformedness (issue #4) is the immediate next
step.

The lemma that DOES verify is `enrollment_required`: every entry the
operator accepts is preceded by an operator-and-producer-co-signed
enrollment confirmation. That part of the protocol is machine-checked
to be correct as modeled.

If a re-run after fixes succeeds, update both this README and
`expected-output.txt`.

Running yourself
----------------

The `--prove` driver OOMs in ~4 GB if it tries every lemma at once on
this model. Run them one at a time:

```sh
tamarin-prover --prove=enrollment_required    --bound=8 stele.spthy
tamarin-prover --prove=forward_secrecy        --bound=8 stele.spthy
tamarin-prover --prove=no_witness_double_cosign --bound=8 stele.spthy
tamarin-prover --prove=sanity_complete_run    --bound=8 stele.spthy
```

If you don't have tamarin locally, the Docker image works:

```sh
docker run --rm --memory=4g \
    -v $(pwd):/work -w /work \
    lmandrelli/tamarin-prover \
    tamarin-prover --prove=enrollment_required --bound=8 stele.spthy
```

If any lemma reports `INDETERMINATE`, the bounded search did not
conclude. Re-run with `--heuristic=O` or `--heuristic=I` to try
alternate search strategies.

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
