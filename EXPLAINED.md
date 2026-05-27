# What is stele? (For people who don't write code)

This document is for executives, lawyers, auditors, regulators, journalists,
and anyone else who wants to understand what stele does and why it matters,
without needing to read source code.

---

## The problem in plain terms

Imagine you're a CEO. Something serious has happened at your company —
maybe a customer data leak, maybe an internal investigation, maybe a
regulator asking you what happened. You ask your IT team for the audit
log: "Show me everything that happened to our customer database last
Tuesday between 2pm and 5pm."

They hand you a file.

Here's the uncomfortable truth almost no one talks about: **you have no
real way to know if that file is honest**. The IT administrator who
logged in last Tuesday at 3pm could have deleted that entry before
handing the file to you. The cloud provider hosting your logs could have
quietly dropped a few records due to a "bug." The attacker who broke in
could have spent an extra five minutes erasing the traces of their
visit. The very person you'd most need the log to expose is often the
person with the most power to alter it.

Audit logs today are like a notebook left on the table at a busy office.
Everyone trusts they're accurate. But anyone with the right access could
quietly tear out a page.

This is not theoretical. In real corporate breaches, the very first
thing sophisticated attackers do is clear the logs. In the SolarWinds
attack (2020), the Microsoft Exchange Server attacks (2021), and many
others, the attackers spent meaningful effort wiping their evidence.
Companies discovered the breaches weeks or months later, with most of
the trail erased. Recently, several large companies have been unable to
fully reconstruct what was stolen in their breaches *because the logs
were tampered with.*

---

## Why current audit logs all have this problem

There are roughly four kinds of audit logs in production use today:

| Kind | Example | Who can rewrite it? |
| ---- | ------- | ------------------- |
| Plain text files | Linux auditd, Windows Event Log | Anyone with admin access on the host |
| Database tables | Custom "events" tables in MySQL/Postgres | Anyone with database write access |
| Cloud audit logs | AWS CloudTrail, GCP Audit Logs | Cloud provider's staff (rare in practice but possible) |
| Enterprise blockchain | Hyperledger Fabric, ConsenSys Quorum | Whoever controls the validator nodes (often back to one company) |

All four share one fatal property: **there's at least one party who can
rewrite history**. Sometimes that's an internal administrator with root,
sometimes a database admin, sometimes a small group at a cloud provider,
sometimes the consortium running the blockchain. Cryptography doesn't
protect the log from the people who hold its keys.

---

## The big idea behind stele

Stele turns the audit log into a *cryptographically tamper-evident*
object. Tamper-evident means: if anyone tampers with it, the tampering
is mathematically detectable — even if they have full control of every
computer the log lives on.

The name comes from ancient Greek stone monuments inscribed with laws
and proclamations. Things like the Code of Hammurabi (3,800 years old)
and the Rosetta Stone (2,200 years old) are still legible today because
they were carved into stone. You can't quietly edit a stone — anyone
looking at it would see the chisel marks.

Stele the software borrows this metaphor: once you write something to a
stele log, you can't quietly change what was written. Anyone checking
later will see the equivalent of chisel marks.

But unlike actual stone (which is heavy, immobile, and can simply be
stolen or smashed), stele uses mathematics and distributed copies to
achieve the same property. To erase a record from stele, you'd have to
break the laws of mathematics AND simultaneously corrupt every one of
several independent parties around the world. The cost goes up
exponentially with each additional witness.

---

## How it works, in everyday analogies

Here's how stele actually achieves this, with each piece explained as if
you were keeping a magical diary you couldn't tamper with.

### 1. Sealed pages

Every page of the diary has, at the top, a number computed from the
exact contents of the previous page. Think of it as a fingerprint. If
you change a single letter on the previous page, that fingerprint
changes — and the fingerprint on the page after it no longer matches.
So if anyone goes back and edits page 47, the broken link to page 48 is
visible to anyone who flips through.

**In stele: the hash chain.** Every entry includes a cryptographic hash
of the entry before it. Editing any past entry is detected.

### 2. The author's signature

Every page is signed by whoever wrote it — not with a regular signature
(which can be forged) but with a *cryptographic* signature using a
unique mathematical key. Anyone can check the signature is real (using
the public version of the key), but only the original author can
produce one.

**In stele: producer attestation.** The application or person writing a
log entry signs it with their own private key. Even the central log
server can't quietly insert a fake entry pretending to come from them.

### 3. The notary's seal

Every minute or so, a notary stamps a seal on the diary that says:
"As of this moment, this diary has 312 pages, and a fingerprint of
ALL the content of all 312 pages is `ABC-123-XYZ`." The seal is signed
so no one can forge it.

**In stele: the checkpoint.** The operator periodically signs a
statement: "the log has size N and a Merkle root R." That single seal
locks in *every entry* in the log up to that moment.

### 4. The witnesses

The diary isn't only sealed by the writer's own notary. Several
*independent* notaries — a customer's auditor, a regulator's watcher, an
open-source watcher — also stamp the diary with their own seals. Each
notary keeps their own log of what they've seen so they can't be
quietly bribed later.

**In stele: the witness mesh.** Independent parties each run a small
program that countersigns the operator's checkpoints. To rewrite
history, an attacker would have to compromise the operator AND a quorum
of witnesses simultaneously, all run by people who don't share
infrastructure or motives.

### 5. The public bulletin board

A copy of every notary seal is posted on a public bulletin board where
anyone in the world can see it. The bulletin board's own integrity is
guaranteed because the town crier reads out the latest postings to a
thousand people every hour — so the bulletin board operator can't
quietly take a posting down.

**In stele: Sigstore Rekor.** A globally public, internet-scale
transparency log run by the Sigstore project (a Linux Foundation
initiative). Hundreds of computers around the world automatically
replicate every entry. To "untell" a story posted there, you'd have to
corrupt the whole network.

### 6. The randomness from a distant tower

Every notary seal also contains a small piece of unpredictable
information broadcast every 3 seconds from a tower a thousand miles
away. Because the tower's broadcasts are unpredictable in advance, the
notary can't pretend to have sealed the diary yesterday — they'd have
needed to know yesterday's broadcast, which was unknowable until the
moment it happened.

**In stele: the drand beacon.** The League of Entropy (universities and
foundations including EPFL, Cloudflare, UCL, and Protocol Labs)
broadcasts a new verifiable random number every 3 seconds. Including a
recent value in a checkpoint cryptographically proves the checkpoint
couldn't have been signed before that moment.

### 7. The notary who forgets

A clever twist: at the end of each day, the notary throws their old
stamp into a furnace. They get issued a fresh stamp the next morning.
The old stamp is unrecoverable.

If an attacker steals the notary's stamp today, they can only forge
today's seals. They cannot go back and forge yesterday's, because
yesterday's stamp no longer exists *anywhere in the world*.

**In stele: forward-secure signing.** The operator's signing key is
rotated periodically, and the previous key is irrevocably destroyed.
A current-key compromise doesn't compromise past signatures.

### 8. The poisoned pages

Some pages of the diary are deliberately fake — they look like the
juiciest information in the diary ("here's where the safe is hidden")
but the contents are tripwires. If anyone reads those pages, an alarm
sounds in the writer's house. The writer instantly knows someone is
snooping.

**In stele: the honeylog.** Entries can be flagged as canaries. Any
lookup of a canary entry fires a webhook alert — exposing the attacker
the moment they read what they were searching for. The flag is part of
the cryptographic hash, so the attacker can't strip the canary marker
without breaking everything else.

---

## What stele lets you prove that you couldn't prove before

Suppose six months from now you're in court, and you need to prove that
on March 14th at 2:43:17 PM, user "alice" granted IAM permission
`AdminAccess` to the service account `deploy-bot`.

**Without stele:** You bring an export of your audit log database. The
opposing lawyer asks "How do we know this wasn't edited?" You say "We
trust our IT team." The judge looks skeptical. You probably lose this
argument.

**With stele:** You bring:

1. The audit log entry itself, showing the event.
2. A mathematical proof that this exact entry is part of a tree whose
   root is `R`.
3. A signed statement from your company that as of 2:44 PM on March
   14th the tree had root `R`.
4. Signed statements from three independent witnesses (your auditor,
   a regulator's monitor, an open-source watcher) all confirming the
   same root `R` at the same time.
5. A record from Sigstore Rekor (publicly archived, replicated across
   hundreds of independent machines worldwide) anchoring root `R` to
   that minute.
6. A piece of randomness from a global beacon embedded in the
   statement, proving cryptographically that the statement was signed
   AFTER 2:44 PM and not retroactively.

That's no longer "trust us." That's mathematical proof. Many of those
parties are themselves under regulatory or legal obligations to keep
their records accurate.

---

## Who would actually use this?

- **Banks and financial institutions** — regulators (SEC, FINRA, ECB)
  require provable audit trails. Stele provides the audit-trail
  property regulators have been asking for since the 2008 crisis.

- **Healthcare providers** — HIPAA mandates audit trails of access to
  protected health information. After a breach, those audit trails are
  often the disputed evidence.

- **Government agencies** — chain of custody for digital evidence.
  Police body-cam footage, surveillance records, public-records requests
  — all need provenance.

- **Cryptocurrency exchanges** — proof of reserves, proof that user
  balances haven't been quietly inflated.

- **Any company with insider threat concerns** — disgruntled admins,
  ex-employees with credentials, malicious offshoring vendors. Stele
  removes "I'll quietly cover my tracks" from their playbook.

- **Any company being sued** — legal-grade evidence integrity changes
  what's admissible.

- **Cloud providers themselves** — sell stele as a feature to customers
  who want to verify the cloud provider's audit logs are real.

- **Investigative journalists** — secure logs of source contacts where
  the journalist needs to prove their notes weren't fabricated later.

- **Software supply chain** — anchoring build artifacts and release
  signatures so attackers can't slip in trojaned versions undetected.

- **Voting systems** — provable audit trails for elections.

- **Scientific research** — provable chain of custody for data in
  reproducibility-critical fields.

---

## Limitations — honest answers

These are real and worth understanding.

**Stele protects integrity, not confidentiality.** Anyone with read
access can still *read* your audit log. If the data is sensitive,
encrypt the contents *before* submitting them to stele. Stele will
preserve the encrypted ciphertext perfectly; only people with the
decryption key can read what's actually in there.

**Stele can't prevent destruction.** A sophisticated attacker who
controls every host (yours + every witness's + Sigstore's) could in
principle stop new entries from being created or prevent witnesses from
issuing new countersignatures. They cannot, however, retroactively
*rewrite* past history without leaving cryptographic evidence.

**Stele is only as strong as the diversity of its witnesses.** If you
run everything yourself — the operator, all the witnesses, all the
anchors — you're back to single-party trust. The strength scales with
how independent and how many your witnesses are. A bank with three
witnesses (their own security team, their regulator, and an
open-source watcher) is much harder to compromise than the same bank
with three witnesses all running on AWS in `us-east-1`.

**Stele can't make up for poor logging.** If your application doesn't
emit an event for some action, stele can't anchor what doesn't exist.
Stele preserves what's logged; it doesn't decide what to log.

**Stele preserves what was logged AT THE TIME, not future
re-interpretation.** If you logged a customer's address poorly (typo,
truncation, encoding error), stele will preserve that imperfect record
forever. It is not a do-over.

---

## Common questions

**Q: Isn't this just a blockchain?**

No, though it shares some primitives. A blockchain achieves integrity
through enormous global energy spend on Proof-of-Work or huge token
economics on Proof-of-Stake. Stele achieves the same integrity property
much more cheaply by having a small number of independent witnesses
plus a public bulletin board. It uses about 0.0001% as much energy as
even a small blockchain.

The cryptographic primitive — Merkle trees + signatures — is the same
one underneath both. Stele just doesn't need the consensus mechanism
that blockchains use to decide *whose* records to keep.

**Q: What stops a bad witness from signing fake checkpoints?**

A witness can only countersign what the operator presents. The
witness's signature attests "I saw the operator sign THIS checkpoint at
this time." A bad witness can sign fraudulent checkpoints, but a good
witness will refuse, and the verifier requires multiple witnesses to
agree. One bad witness in a cohort of five just gets ignored.

**Q: What if the operator's key gets stolen?**

This is exactly what the forward-secure signing layer prevents. Today's
key cannot forge yesterday's signatures, because yesterday's key was
destroyed. The current-day damage is limited to "until the breach is
detected and a new epoch is rotated to," typically minutes-to-hours.

**Q: What if Sigstore Rekor itself is corrupted?**

Sigstore Rekor is itself a transparency log with its own witness
network — Google, Chainguard, multiple universities, independent
operators. To corrupt Rekor you'd need to corrupt all of them. And even
if you did, your stele log still has its own witness network — Sigstore
is one defense layer of several.

**Q: How fast is it?**

A single stele operator on a modest server can handle thousands of
append operations per second. Checkpoints take seconds. Anchoring takes
seconds. The whole system is designed to be cheap to run.

**Q: How expensive is it?**

Operator: a small VM (1 vCPU, 2 GB RAM) is enough for most workloads.
Witnesses: even smaller — a Raspberry Pi has enough power. Sigstore
Rekor: free, public, run by the Linux Foundation. So: very cheap. The
main cost is operational discipline (running the witnesses on
infrastructure independent from the operator).

**Q: Does this work with existing applications?**

Yes — the simplest integration is a logging library wrapper. Your
application calls `stele.Log("event description")` instead of (or in
addition to) `logger.Info(...)`. Existing log-collection pipelines
(syslog, Fluentd, Vector) can be wired in too.

**Q: What's the legal status?**

Stele's cryptographic guarantees produce evidence that meets the rules
of evidence standards in most common-law jurisdictions (Federal Rules
of Evidence in the US, similar standards in the EU and UK). The
specific admissibility depends on jurisdiction, but the property
stele provides — independent verifiability of a digital record —
is exactly what courts have been asking software vendors to provide
for two decades.

**Q: Why has nobody built this before?**

The cryptographic primitives have existed since the early 2000s.
Certificate Transparency (Google, 2013), Sigstore Rekor (Linux
Foundation, 2021), and several others use the same building blocks for
narrower use cases (TLS certificates and software signatures
respectively). The combination of all of these into a turnkey
*application audit log* — with producer attestation, forward-secure
signing, drand time anchoring, and witness mesh — is what stele is. The
parts have all been there; the integration into a single deployable
tool is the new thing.

---

## Summary in one paragraph

Stele is an audit-log system where you can prove what happened —
mathematically — even if the person who runs the log server is the one
who tried to hide it. It does this by combining cryptographic signatures
on every entry, a hash chain linking entries together, periodic signed
"checkpoints" of the whole log, independent witnesses who countersign
those checkpoints, a public transparency log (Sigstore Rekor) where
checkpoints get anchored, a randomness beacon that prevents
backdating, and a key-rotation scheme that means even key theft today
can't forge yesterday's signatures. It is to audit logs what carving in
stone was to writing on paper — except faster, cheaper, and harder to
forge.
