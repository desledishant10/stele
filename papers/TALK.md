# Stele — Conference Talk Outline

Working title and outline for a 30-minute talk at a security
conference. Reusable across venues with minor adjustments.

## Suggested venues

| Venue | Why | Format |
|---|---|---|
| **FOSDEM Security devroom** | Open-source, technical audience; demo-friendly | 30 min + Q&A |
| **USENIX Security (paper talk)** | If/when the paper lands | 25 min talk |
| **Black Hat USA** | High-visibility; can sell to enterprise security teams | 50 min |
| **DEF CON village (e.g. AppSec, Cryptography, Blue Team)** | Underground community + practitioners | 30 min |
| **Real World Crypto** | If we have the formal-verification angle published | 30 min |
| **PyCon / NodeConf / GopherCon** | SDK-focused, draws producers in each language | 20-30 min |

The pitch is the same; what varies is the time spent on protocol
internals vs. demo vs. compliance angle.

## Working title

> **"How to Make Your Audit Log Survive Your Own SRE"** — a
> tamper-evident audit log even your most-privileged insider can't
> rewrite.

(Alternatives: "Audit logs auditors actually trust"; "Tamper-evident
logs without a blockchain"; "Stele: provenance-anchored audit logs
in 30 minutes".)

## Audience takeaways (what they should remember in a week)

1. **Most audit logs are operationally protected, not
   cryptographically protected.** A motivated insider with root on
   the log host can rewrite history.
2. **There's a known protocol family that fixes this** — RFC 6962
   Merkle trees + witness networks + forward-secure rotation. CT did
   this for certificates; stele does it for arbitrary logs.
3. **You can run this today.** Three deployment paths (Docker,
   Helm, systemd); SDKs in Go, Python, TypeScript; signed releases.
4. **The cryptographic claims are machine-checked.** Tamarin model
   ships in `formal/`.

## Talk structure (30 minutes)

### 0:00 — Cold open (2 min)

A real-ish scenario:

> "Imagine: your CISO is on the phone with a regulator. The
> regulator says 'show me every access to file X.'  You hand them
> your log.  They say 'how do I know you didn't just delete the
> rows you didn't want me to see?'"
>
> "If your answer is 'trust us' — you don't have an audit log. You
> have a database with the word AUDIT in the schema."

Get the laugh, get the room.

### 2:00 — What an audit log actually needs (3 min)

- Append-only: no edits, no deletes
- Tamper-evident: any change is detectable
- Non-repudiable: a third party can verify
- Independent: not just "trust the operator"

CT had this for certificates. Sigstore Rekor for software releases.
But for ARBITRARY logs (your access logs, your security alerts,
your compliance trail) — nothing.

### 5:00 — Stele: the elevator pitch (3 min)

One slide:

```
              ┌──────────────┐
              │  Producers   │  → sign envelopes
              └──────┬───────┘
                     │
                     ▼
     ┌─────────────────────────────────┐
     │  Operator (steled)              │
     │  ├─ append to hash chain        │
     │  ├─ Merkle tree                 │
     │  ├─ sign checkpoints            │
     │  └─ anchor to Rekor + drand     │
     └────┬──────┬──────┬──────────────┘
          │      │      │
          ▼      ▼      ▼
       ┌────┐ ┌────┐ ┌────┐
       │ W1 │ │ W2 │ │ W3 │  ← witnesses cosign each checkpoint
       └────┘ └────┘ └────┘
       independent infrastructure
```

13 defence layers. Five of them are unique to stele in this
combination: forward-secure rotation, witness mesh, threshold, hybrid
PQ, proof-of-possession enrollment.

### 8:00 — Live demo (8 min)

This is the part that sells the talk. Use the devcontainer:

```sh
.devcontainer/try-stele.sh
```

Shows in real time:
1. Operator starting, /readyz green
2. Producer enrolling (the PoP ceremony)
3. Five entries logged
4. `stele audit --pdf` producing a real PDF on screen
5. Showing the PDF in the panel — verdict PASS

Then: kill the operator's BadgerDB out-of-band (the chaos rig has
this), restart, watch the tripwire fire.

### 16:00 — Three things make this different (5 min)

Skip the rest of the 13 — show the three that nobody else combines:

1. **Forward-secure rotation.** Visualise the chain. The operator's
   key from yesterday is GONE. Even compromising the operator host
   today doesn't let you forge yesterday's signatures.
2. **Witness mesh.** Show the gossip diagram. A forking operator
   shows different roots to different witnesses; the witnesses
   compare notes and BOTH have signed evidence of the inconsistency.
3. **Proof-of-possession enrollment.** Producer signs operator's
   challenge; operator signs producer's identity; admin log
   captures the artifact. Provable mutual consent.

### 21:00 — Formal verification (3 min)

Show `formal/stele.spthy` on screen. Highlight the three lemmas.
Run `tamarin-prover --prove` if conference WiFi cooperates.

> "We didn't just write code that we *hope* has these properties.
> We have a machine-checked proof that the protocol does."

This is the slide that lands for the academic / cryptography
audience.

### 24:00 — How you'd actually adopt this (3 min)

90-day plan from ADOPTING.md:
- Days 1-30: pilot with one log
- Days 31-60: production rollout
- Days 61-90: hand-off

Show the compliance mapping screen briefly: stele maps to N rows of
SOC 2, NIST, ISO. Procurement-friendly.

### 27:00 — Where the gaps are (2 min)

Be honest. The talk lands better with disclosed limitations:
- Not (yet) certified by anyone
- Single-node operator at v0.1
- No 72-hour soak completed yet
- WAL batching for >10K rps is future work

### 29:00 — Where to find it (1 min)

- github.com/desledishant10/stele
- `docker pull ghcr.io/desledishant10/stele:0.1.0`
- One-click try-it: GitHub Codespace from the repo

### 29:30 — Q&A

## Slide deck structure (suggested)

20 slides max. Heavy on diagrams + live demo, light on bullet
points.

1. Title + speaker
2. Cold open (one quote, one image)
3. What an audit log needs (4 bullets, then "...most don't have")
4. RFC 6962 family
5. Stele diagram (the architecture slide above)
6. Live demo slide ("...let's see this for real")
7. Forward-secure rotation diagram
8. Witness mesh + gossip diagram
9. Enrollment ceremony sequence diagram
10. Tripwire firing screenshot
11. Tamarin lemma list
12. SDK code samples (Python, TS, Go side-by-side)
13. Deployment paths (Docker / Helm / systemd icons)
14. Compliance mapping screenshot
15. 90-day adoption timeline
16. Honest limitations
17. Performance numbers
18. Future work (one slide)
19. Resources (the repo + signed binaries + paper)
20. Q&A

## Q&A preparation

| Anticipated question | Short answer |
|---|---|
| "Why not blockchain?" | We anchor to Sigstore Rekor (which is itself a transparency log); that's the part of "blockchain" that matters for audit logs. We don't need the consensus or the gas fees. |
| "Why not just Splunk?" | Splunk is operationally protected, not cryptographically protected. An admin with the right access can delete entries. Stele's threat model assumes that admin is the attacker. |
| "What about HIPAA / PCI / SOC 2?" | We have a control mapping ([COMPLIANCE.md](../COMPLIANCE.md)). Stele is a *control implementation*; you still need the broader compliance program. |
| "How fast is it?" | ~7K appends/sec single-node fsync-bound today; WAL batching in the roadmap could push that 10x. Stele's positioning is correctness over throughput; if you need 100K/s, use a sharded deployment. |
| "What's the catch?" | Append-only. No edits. No deletions. If your workflow assumes you can fix a typo in a logged event, stele isn't the tool. |
| "Why hybrid PQ today?" | Defence in depth + future-proofing. Dilithium3 / ML-DSA Level 3 is a NIST FIPS 204 standard now. Two signatures is cheap; one of them surviving a future cryptanalytic break is invaluable. |
| "How are you funding this?" | Open-source project; the talk is community-supported. No commercial offering today; adoption is voluntary. |

## Recording considerations

- Pre-record the live demo as a backup. Conference WiFi.
- Slides should still be readable from the back row.
- Make sure the screen showing the audit PDF is large enough to
  actually see the PASS verdict.
- Have a 5-minute and a 10-minute cut ready in case the chair cuts
  short.
