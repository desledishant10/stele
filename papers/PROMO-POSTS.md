# Promo post drafts — v0.1.2

Ready-to-paste content for the four venues we agreed to seed. Honest
framing throughout; nothing claims more than the current artifact
backs up. Copy-paste, edit, then post.

**Read this before posting:** the formal model currently has two
lemmas that falsify in `tamarin-prover` (issues #4-#6). That makes
**r/cryptography risky** until those land. The other three venues
are safe.

---

## Hacker News - "Show HN"

**Title** (<= 80 chars):

> Show HN: Stele - a tamper-evident audit log even your root user can't rewrite

**URL field:** `https://github.com/desledishant10/stele`

**Text:** (only filled in if HN's title-only mode isn't preferred)

> Most "audit logs" are operationally protected, not cryptographically
> protected. A motivated insider with root on the log host can edit or
> delete rows and there's no way for a third party to detect it.
>
> Stele is an attempt to do for arbitrary logs what Certificate
> Transparency did for certificates: a hash-chained, Merkle-tree-rooted
> append-only log, signed with forward-secure operator keys that get
> destroyed after rotation, countersigned by an independent witness
> mesh, and anchored to public transparency logs (Sigstore Rekor +
> drand).
>
> What's interesting if you're a HN reader:
>
>   - Three SDKs (Go, Python, TypeScript) with byte-for-byte cross-
>     language envelope interop, validated against the Go reference
>     server on every CI run + 36 deterministic KAT vectors
>   - Hybrid post-quantum signatures (Ed25519 + Dilithium3) at every
>     signature site
>   - Tamarin protocol model in `formal/` -- and I'll be honest: of
>     the 3 security lemmas, currently 1 verifies and 2 falsify in
>     the prover (issues #4-#6); we're debugging whether that's a
>     model error or a real flaw. The transcript is checked in.
>   - SLSA Build L3 release artifacts, multi-platform binaries,
>     Sigstore-signed Docker image, 30-second devcontainer demo
>
> What I'm explicitly NOT claiming yet:
>
>   - No third-party security audit (the kit's prepared in AUDIT-KIT.md)
>   - No completed 72-hour soak (orchestration's in soak/, just hasn't
>     run on a real VM yet)
>   - Single-node operator at this version; sharded deployment is roadmap
>
> Apache 2.0; one-click try-it: open the repo in a Codespace and run
> `.devcontainer/try-stele.sh`. Feedback especially welcome on the
> Tamarin model.

---

## Lobsters

**Title:**

> Stele: a tamper-evident audit log with forward-secure operator keys, witness mesh, and hybrid PQ signatures

**Category tags:** `security`, `cryptography`, `go`

**URL:** `https://github.com/desledishant10/stele`

**Description text (Lobsters supports markdown):**

> v0.1.x of a project I've been calling stele: a hash-chained append-
> only audit log with forward-secure operator keys (rotated and
> destroyed) + an independent witness mesh + hybrid PQ at every
> signature site. CT-family, not blockchain.
>
> Things Lobsters readers might find worth poking at:
>
> - Three SDKs (Go / Python / TypeScript) with deterministic cross-
>   language envelope interop tested in CI -- the Python signer
>   produces bytes the Go server accepts unchanged.
> - Tamarin model in `formal/` -- with the honest caveat that 2 of 3
>   lemmas currently falsify in the prover and we have an open issue
>   tree tracking it.
> - SLSA L3 build provenance + Sigstore keyless signatures on every
>   binary in the release.
> - One-click try-it via Codespace devcontainer.
>
> Things still open: no completed 72-hour soak yet, no third-party
> audit yet, single-node operator. v0.1.x is pre-production.

---

## Reddit r/golang

**Title:**

> [Show /r/golang] Stele: a 7K-rps tamper-evident audit log in pure Go

**Body:**

> Hi all. Sharing a project I've been building called stele: a
> tamper-evident audit log with the protocol family that CT and
> Sigstore use, applied to arbitrary logs instead of just
> certificates / software releases.
>
> Pure-Go reference implementation; all the cryptography is from the
> standard library + `golang.org/x/crypto`. CGO is optional (used
> only when you want the HSM path).
>
> Things Gophers might enjoy:
>
> - `go install github.com/desledishant10/stele/cmd/stele@v0.1.2`
> - reproducible builds via `-trimpath -ldflags="-buildid="`, verified
>   in CI on every release (workflow re-builds and diffs hashes)
> - SLSA Build L3 provenance attestations attached to each release
> - 7,000+ appends/sec single-node, fsync-bound -- benchmarks in
>   `bench/baseline.txt`
> - Tamarin protocol model in `formal/` (with the honest caveat that
>   not every lemma currently passes; investigation tracked in #4-#6)
> - Property + fuzz + chaos tests across `pkg/` (race detector on
>   by default in `make test`)
>
> Apache 2.0. Feedback on Go-specific stuff (API ergonomics, the
> threading model in `pkg/core/log.go`, the `errgroup` patterns in
> the witness mesh) especially welcome.

---

## /r/cryptography (HOLD until #4-#6 are fixed)

> **Don't post this yet.** Crypto-savvy readers will run tamarin and
> notice the falsifying lemmas inside an hour, and the post becomes
> "amateur hour" instead of "interesting honest engineering."
>
> Reasonable timeline: post to r/cryptography after we land at least
> #4 (the wellformedness fix), even if forward_secrecy still
> ultimately falsifies as a real protocol observation. At that point
> we'd have either:
>   - a clean tamarin run (best case), or
>   - a clean tamarin run + concrete model-level falsification trace
>     (still interesting, just in a different way)
>
> Either is postable. The current "2 of 3 lemmas falsify because of
> a model bug" state is NOT.

---

## Twitter / X thread (optional)

(One-shot tweet OR a 4-tweet thread, depending on your platform
preference.)

**Single tweet:**

> stele v0.1.2 is out: a tamper-evident audit log with forward-secure
> operator keys, an independent witness mesh, hybrid PQ signatures,
> and CT-family transparency anchoring. One `docker pull` to try.
>
> https://github.com/desledishant10/stele

**Thread (more honest, more attention-getting):**

> 1/ Most audit logs are operationally protected, not cryptographically
>    protected. If your CISO calls you when a regulator asks "how do
>    we know you didn't just delete the rows you didn't want us to see"
>    -- the right answer can't be "trust us."
>
> 2/ Stele: a hash-chained, Merkle-rooted, forward-secure-signed,
>    witness-mesh-cosigned audit log. CT + Sigstore family, not
>    blockchain. v0.1.2 just shipped.
>
> 3/ Three SDKs (Go, Python, TypeScript) with deterministic cross-
>    language envelope interop tested on every CI run. Apache 2.0.
>    Codespace demo runs end-to-end in 30 seconds.
>
> 4/ Honest open items: 72h soak run is pending, third-party audit
>    is pending, and the Tamarin model has 2 of 3 lemmas currently
>    falsifying (we found this when we actually ran the prover and
>    the receipts are checked in). Pre-production. Help wanted.
>
>    https://github.com/desledishant10/stele

---

## Post-success follow-ups

If any post takes off, hand-write a thank-you reply that links to:
- AUDIT-KIT.md for security-minded readers
- ADOPTING.md for "OK, how do I actually use this"
- formal/README.md for cryptographer readers

And resist the urge to oversell in the replies. The framing of v0.1.x
is "production-shape but pre-soak; we'd love adopters who understand
that distinction."
