// Package core wires the persistence layer, the in-memory Merkle tree, the
// checkpoint signer, and one or more anchor sinks into a single Log object.
//
// Append() is the only mutation. Every other method is read-only and safe
// to call concurrently with itself, though only one Append may be in flight
// at a time per Log instance.
package core

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/merkle"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
)

// Log is the running provenance-log instance.
type Log struct {
	store              *storage.Store
	tree               *merkle.Tree
	signer             *checkpoint.Signer
	sinks              []anchor.Sink
	beacon             CheckpointBeaconFetcher
	requireEnrollment  bool

	mu sync.Mutex // serialises Append + tree mutation

	// Pending enrollments awaiting producer-side challenge response.
	// In-memory only — if steled restarts mid-ceremony, the producer
	// just retries.
	pendingMu  sync.Mutex
	pending    map[string]*pendingEnrollment
}

// pendingEnrollment is the server-side state of an in-flight
// challenge-response enrollment ceremony. Created by BeginEnrollment,
// consumed (atomically) by ConfirmEnrollment.
type pendingEnrollment struct {
	challengeID [16]byte
	prod        *storage.Producer // pre-built record; classical/quantum challenge sigs filled at Confirm
	expiresAt   time.Time
}

// defaultChallengeTTL bounds how long a producer has to respond to a
// challenge before it must request a new one. Short enough that a
// leaked challenge isn't useful for long; long enough that real
// network latency + human-in-the-loop CLIs work fine.
const defaultChallengeTTL = 5 * time.Minute

// Options configures a Log.
type Options struct {
	Store         *storage.Store
	Signer        *checkpoint.Signer
	Sinks         []anchor.Sink
	BeaconFetcher CheckpointBeaconFetcher // optional public randomness

	// RequireEnrollment, when true, refuses Append for any producer
	// that doesn't carry a verifiable signed enrollment from the
	// operator's chain. Legacy registry-only producers (no Signature)
	// are rejected with "enrollment required" — operators migrating
	// must re-issue every producer via IssueEnrollment before flipping
	// this flag.
	RequireEnrollment bool
}

// New constructs a Log and replays every entry from the store to rebuild
// the in-memory Merkle tree. Replay is O(N) and integrity-checks the chain
// as it goes — if the on-disk log has been tampered with, Open will fail.
func New(ctx context.Context, opts Options) (*Log, error) {
	if opts.Store == nil {
		return nil, errors.New("core: Store is required")
	}
	if opts.Signer == nil {
		return nil, errors.New("core: Signer is required")
	}
	l := &Log{
		store:             opts.Store,
		tree:              merkle.NewTree(),
		signer:            opts.Signer,
		sinks:             opts.Sinks,
		beacon:            opts.BeaconFetcher,
		requireEnrollment: opts.RequireEnrollment,
		pending:           make(map[string]*pendingEnrollment),
	}
	if err := l.replay(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

// replay walks every persisted entry, validates its self-hash and its chain
// link to the previous entry, and re-appends the leaf hash to the in-memory
// Merkle tree. Any failure aborts startup so a tampered DB cannot serve
// proofs.
func (l *Log) replay(ctx context.Context) error {
	var prev *logentry.Entry
	count := 0
	err := l.store.IterateEntries(ctx, 0, func(e *logentry.Entry) error {
		if err := e.Verify(); err != nil {
			return fmt.Errorf("replay: entry %d failed self-verify: %w", e.Index, err)
		}
		if err := e.VerifyChain(prev); err != nil {
			return fmt.Errorf("replay: %w", err)
		}
		l.tree.AppendLeafHash(e.LeafHash)
		prev = e
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if uint64(count) != l.tree.Size() {
		return fmt.Errorf("replay: tree size %d != entries replayed %d",
			l.tree.Size(), count)
	}
	return nil
}

// Size returns the number of entries in the log.
func (l *Log) Size() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.Size()
}

// Root returns the current Merkle root.
func (l *Log) Root() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.Root()
}

// Origin returns the human label associated with this log instance.
func (l *Log) Origin() string { return l.signer.Origin() }

// PublicKey returns the active epoch's public key.
func (l *Log) PublicKey() []byte { return append([]byte(nil), l.signer.Public()...) }

// Signer exposes the checkpoint signer for advanced operations (rotation,
// key chain inspection).
func (l *Log) Signer() *checkpoint.Signer { return l.signer }

// Append validates a producer-signed envelope against the producer
// registry, wraps it in an entry, persists it, and updates the in-memory
// Merkle tree atomically. On any failure the on-disk state is unchanged.
//
// honeypot, when true, marks the entry as a canary so the honeylog layer
// can fire an alert if anyone looks it up. The flag is part of the
// canonical hash so the operator cannot quietly remove a honey mark.
func (l *Log) Append(env *attest.Envelope, honeypot bool) (*logentry.Entry, error) {
	return l.AppendCtx(context.Background(), env, honeypot)
}

// AppendCtx is Append with caller-provided context so HTTP handlers
// can propagate the trace span downward. New code should prefer this
// over the context-less Append wrapper.
func (l *Log) AppendCtx(ctx context.Context, env *attest.Envelope, honeypot bool) (*logentry.Entry, error) {
	ctx, span := obs.StartSpan(ctx, "stele.append")
	defer span.End()
	start := time.Now()
	outcome := "error"
	defer func() {
		obs.SetAttrs(ctx, obs.AttrString("stele.append.outcome", outcome))
		obs.AppendsTotal.WithLabelValues(outcome).Inc()
		obs.AppendDurationSeconds.Observe(time.Since(start).Seconds())
	}()
	if env == nil {
		outcome = "rejected"
		return nil, errors.New("core: nil envelope")
	}
	if err := env.Verify(); err != nil {
		outcome = "rejected"
		return nil, fmt.Errorf("core: envelope rejected: %w", err)
	}
	// Producer must be registered + not revoked + key(s) must match.
	prod, err := l.store.GetProducer(env.ProducerID)
	if err != nil {
		outcome = "rejected"
		return nil, err
	}
	if prod.Revoked {
		outcome = "rejected"
		return nil, fmt.Errorf("core: producer %q is revoked", env.ProducerID)
	}
	if !bytesEqual(prod.PublicKey, env.PublicKey) {
		outcome = "rejected"
		return nil, fmt.Errorf("core: producer %q classical public key mismatch", env.ProducerID)
	}
	// Hybrid binding: if the producer was registered with a quantum
	// pubkey, the envelope MUST also carry one and it MUST match.
	if len(prod.QuantumPublicKey) > 0 {
		if len(env.QuantumPublicKey) == 0 {
			outcome = "rejected"
			return nil, fmt.Errorf("core: producer %q is registered as hybrid but envelope has no quantum_public_key (downgrade attempt?)", env.ProducerID)
		}
		if !bytesEqual(prod.QuantumPublicKey, env.QuantumPublicKey) {
			outcome = "rejected"
			return nil, fmt.Errorf("core: producer %q quantum public key mismatch", env.ProducerID)
		}
	}
	// Enrollment check: when enabled, every producer must carry a
	// valid signed enrollment against the operator's chain. This
	// upgrades the registry from "trusted JSON blob" to "cryptographic
	// attestation" — a disk-tamper or hostile admin call can't insert
	// a producer without the operator chain key.
	if l.requireEnrollment {
		if !prod.HasEnrollment() {
			outcome = "rejected"
			return nil, fmt.Errorf("core: producer %q has no enrollment but --require-enrollment is on", env.ProducerID)
		}
		if prod.IsExpired(time.Now()) {
			outcome = "rejected"
			return nil, fmt.Errorf("core: producer %q enrollment expired at %d", env.ProducerID, prod.ExpiresAt)
		}
		chain := l.signer.Chain()
		if err := prod.VerifyEnrollment(chain.PublicKeyAt, chain.QuantumPublicKeyAt); err != nil {
			outcome = "rejected"
			return nil, fmt.Errorf("core: producer %q enrollment invalid: %w", env.ProducerID, err)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	idx := l.tree.Size()
	// Replay protection: refuse an envelope hash we've already accepted.
	// envelope.Hash() is a deterministic SHA-256 of the producer-
	// canonical bytes — re-submitting the same envelope produces the
	// same hash. This closes the "network attacker records a past
	// valid request and replays it later" attack.
	if err := l.store.CheckAndRecordEnvelope(env.Hash(), idx); err != nil {
		outcome = "duplicate"
		return nil, fmt.Errorf("core: %w", err)
	}
	head, err := l.store.HeadHash()
	if err != nil {
		return nil, err
	}
	prevEntry := &logentry.Entry{Index: idx - 1, EntryHash: head}
	if idx == 0 {
		prevEntry = nil
	}

	entry := logentry.New(idx, prevEntry, env, honeypot)
	if err := l.store.AppendEntry(entry); err != nil {
		return nil, err
	}
	l.tree.AppendLeafHash(entry.LeafHash)
	outcome = "ok"
	obs.TreeSize.Set(float64(l.tree.Size()))
	if honeypot {
		obs.HoneypotsTotal.Inc()
	}
	return entry, nil
}

// RegisterProducer adds or updates a producer in the registry. Re-using an
// existing ID rotates the producer key — old entries remain valid because
// their envelope carries the public key it was actually signed by, but
// future entries must use the new key.
//
// NOTE: in enrollment mode (see IssueEnrollment), prefer that path so
// the producer record is cryptographically anchored to the operator's
// chain. RegisterProducer is the legacy / quick-test entry point.
func (l *Log) RegisterProducer(p *storage.Producer) error {
	return l.store.RegisterProducer(p)
}

// EnrollmentRequest is the input to IssueEnrollment. The operator's
// active fwdsec key signs the resulting Producer record.
type EnrollmentRequest struct {
	ID               string
	PublicKey        []byte
	QuantumPublicKey []byte // optional; required in hybrid producer mode
	AttestationType  string
	Description      string
	Scope            string
	// Validity is how long the enrollment is good for. Zero = never
	// expires (treat as "until revoked").
	Validity time.Duration
}

// IssueEnrollment mints a signed enrollment for a producer and stores
// it. Returns the signed Producer record so callers can ship it back
// to the producer-operator team for sealing alongside the producer's
// private key.
//
// In hybrid mode (operator chain has a Dilithium pubkey at the active
// epoch AND req.QuantumPublicKey is non-empty), the enrollment is
// signed twice: classical + Dilithium3.
func (l *Log) IssueEnrollment(req EnrollmentRequest) (*storage.Producer, error) {
	if req.ID == "" {
		return nil, errors.New("enrollment: ID required")
	}
	if len(req.PublicKey) == 0 {
		return nil, errors.New("enrollment: PublicKey required")
	}
	fws := l.signer.UnsafeFWS()
	chain := fws.Chain()
	now := time.Now().UnixNano()
	expires := int64(0)
	if req.Validity > 0 {
		expires = now + req.Validity.Nanoseconds()
	}
	prod := &storage.Producer{
		ID:               req.ID,
		PublicKey:        append([]byte(nil), req.PublicKey...),
		QuantumPublicKey: append([]byte(nil), req.QuantumPublicKey...),
		AttestationType:  req.AttestationType,
		Description:      req.Description,
		Scope:            req.Scope,
		IssuedAt:         now,
		ExpiresAt:        expires,
		OperatorEpoch:    chain.ActiveEpoch(),
		RegisteredAt:     now,
	}
	canon := prod.CanonicalEnrollment()
	// Sign with the active epoch's classical key.
	epoch, sig, err := fws.Sign(canon)
	if err != nil {
		return nil, fmt.Errorf("enrollment classical sign: %w", err)
	}
	if epoch != chain.ActiveEpoch() {
		// Defence in depth: fws.Sign should always sign with the
		// active epoch but we belt-and-brace.
		return nil, fmt.Errorf("enrollment signed by epoch %d, expected active %d", epoch, chain.ActiveEpoch())
	}
	prod.Signature = sig
	// Hybrid: if both operator chain and producer have quantum keys,
	// also Dilithium-sign.
	if fws.Hybrid() && len(req.QuantumPublicKey) > 0 {
		qsig, err := fws.QuantumSign(canon)
		if err != nil {
			return nil, fmt.Errorf("enrollment quantum sign: %w", err)
		}
		prod.QuantumOperatorPubKey = append([]byte(nil), chain.QuantumPublicKeyAt(prod.OperatorEpoch)...)
		prod.QuantumSignature = qsig
	}
	if err := l.store.RegisterProducer(prod); err != nil {
		return nil, err
	}
	return prod, nil
}

// BeginEnrollmentResult is the server's response to BeginEnrollment.
// The producer signs ChallengeBytes with the private key matching the
// PublicKey they submitted; then they call ConfirmEnrollment with
// (ChallengeID, classical signature, optional quantum signature).
type BeginEnrollmentResult struct {
	ChallengeID    string    `json:"challenge_id"`
	ChallengeBytes []byte    `json:"challenge_bytes"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// BeginEnrollment is the first half of the proof-of-possession
// enrollment ceremony. It builds the canonical enrollment record AND
// a server-issued nonce, returning the bytes the producer must sign.
// Until ConfirmEnrollment completes (within defaultChallengeTTL),
// nothing is written to durable storage.
func (l *Log) BeginEnrollment(req EnrollmentRequest) (*BeginEnrollmentResult, error) {
	if req.ID == "" {
		return nil, errors.New("enrollment: ID required")
	}
	if len(req.PublicKey) == 0 {
		return nil, errors.New("enrollment: PublicKey required")
	}
	chain := l.signer.Chain()
	now := time.Now().UnixNano()
	expires := int64(0)
	if req.Validity > 0 {
		expires = now + req.Validity.Nanoseconds()
	}

	// 16 random bytes for the challenge ID (used as the pending-state
	// key); 32 random bytes for the nonce bound into the signed
	// payload.
	var idRaw [16]byte
	if _, err := cryptorand.Read(idRaw[:]); err != nil {
		return nil, fmt.Errorf("enrollment: nonce: %w", err)
	}
	nonce := make([]byte, 32)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, fmt.Errorf("enrollment: nonce: %w", err)
	}

	prod := &storage.Producer{
		ID:               req.ID,
		PublicKey:        append([]byte(nil), req.PublicKey...),
		QuantumPublicKey: append([]byte(nil), req.QuantumPublicKey...),
		AttestationType:  req.AttestationType,
		Description:      req.Description,
		Scope:            req.Scope,
		IssuedAt:         now,
		ExpiresAt:        expires,
		OperatorEpoch:    chain.ActiveEpoch(),
		RegisteredAt:     now,
		ChallengeNonce:   nonce,
	}
	challenge := prod.ChallengeBytes()
	if len(challenge) == 0 {
		return nil, errors.New("enrollment: failed to build challenge bytes")
	}

	chID := hex.EncodeToString(idRaw[:])
	expiresAt := time.Now().Add(defaultChallengeTTL)

	l.pendingMu.Lock()
	l.pending[chID] = &pendingEnrollment{
		challengeID: idRaw,
		prod:        prod,
		expiresAt:   expiresAt,
	}
	l.pendingMu.Unlock()

	return &BeginEnrollmentResult{
		ChallengeID:    chID,
		ChallengeBytes: challenge,
		ExpiresAt:      expiresAt,
	}, nil
}

// ConfirmEnrollment is the second half: verify the producer's
// signature(s) over the challenge, then sign the canonical enrollment
// with the operator's chain key and persist. Returns the fully signed
// Producer record (carrying BOTH the producer's challenge response
// AND the operator's enrollment signature).
//
// Atomic: a successful confirm consumes the pending state; replays
// against the same challenge_id return "unknown or expired challenge".
func (l *Log) ConfirmEnrollment(challengeID string, classicalSig, quantumSig []byte) (*storage.Producer, error) {
	l.pendingMu.Lock()
	pending, ok := l.pending[challengeID]
	if ok {
		delete(l.pending, challengeID) // single-use; consume on lookup
	}
	l.pendingMu.Unlock()

	if !ok {
		return nil, errors.New("enrollment: unknown or expired challenge")
	}
	if time.Now().After(pending.expiresAt) {
		return nil, errors.New("enrollment: challenge expired")
	}

	prod := pending.prod
	prod.ChallengeSignature = append([]byte(nil), classicalSig...)
	if len(prod.QuantumPublicKey) > 0 {
		if len(quantumSig) == 0 {
			return nil, errors.New("enrollment: hybrid producer requires quantum signature on challenge")
		}
		prod.QuantumChallengeSignature = append([]byte(nil), quantumSig...)
	}

	// Verify the producer's consent (signature(s) over the challenge).
	if err := prod.VerifyConsent(); err != nil {
		return nil, fmt.Errorf("enrollment: producer consent: %w", err)
	}

	// Producer is proven to control the private key AND committed to
	// these terms. Now the operator signs the canonical enrollment.
	fws := l.signer.UnsafeFWS()
	canon := prod.CanonicalEnrollment()
	epoch, sig, err := fws.Sign(canon)
	if err != nil {
		return nil, fmt.Errorf("enrollment: operator sign: %w", err)
	}
	if epoch != prod.OperatorEpoch {
		return nil, fmt.Errorf("enrollment: operator epoch drift (signed %d, expected %d)", epoch, prod.OperatorEpoch)
	}
	prod.Signature = sig
	if fws.Hybrid() && len(prod.QuantumPublicKey) > 0 {
		qsig, err := fws.QuantumSign(canon)
		if err != nil {
			return nil, fmt.Errorf("enrollment: operator quantum sign: %w", err)
		}
		prod.QuantumOperatorPubKey = append([]byte(nil), l.signer.Chain().QuantumPublicKeyAt(prod.OperatorEpoch)...)
		prod.QuantumSignature = qsig
	}
	if err := l.store.RegisterProducer(prod); err != nil {
		return nil, err
	}
	return prod, nil
}

// StartEnrollmentJanitor evicts expired pending challenges every
// interval. Cancel ctx to stop. No-op if there's no enrollment work.
func (l *Log) StartEnrollmentJanitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 1 * time.Minute
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				l.pendingMu.Lock()
				now := time.Now()
				for id, p := range l.pending {
					if now.After(p.expiresAt) {
						delete(l.pending, id)
					}
				}
				l.pendingMu.Unlock()
			}
		}
	}()
}

// RevokeProducer prevents future appends from a producer. `reason` is
// recorded alongside for audit (free-form, e.g. "key compromised").
func (l *Log) RevokeProducer(id, reason string) error {
	return l.store.RevokeProducer(id, reason)
}

// ListProducers enumerates the registered producers.
func (l *Log) ListProducers(fn func(*storage.Producer) error) error {
	return l.store.ListProducers(fn)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Get returns the entry at the given index.
func (l *Log) Get(idx uint64) (*logentry.Entry, error) {
	return l.store.GetEntry(idx)
}

// InclusionProof returns a proof that the entry at `idx` is committed by the
// Merkle root for tree size `treeSize`.
func (l *Log) InclusionProof(idx, treeSize uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.InclusionProof(idx, treeSize)
}

// ConsistencyProof proves the tree of size `oldSize` is a prefix of the
// tree of size `newSize`.
func (l *Log) ConsistencyProof(oldSize, newSize uint64) ([][]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tree.ConsistencyProof(oldSize, newSize)
}

// CheckpointBeaconFetcher is a hook that fetches a recent public
// randomness value to embed in checkpoints. nil means "no beacon."
type CheckpointBeaconFetcher func() (*checkpoint.Beacon, error)

// MaxClockSkew is the maximum allowed divergence between the operator's
// wall clock at signing time and the beacon round's expected
// timestamp. A checkpoint whose operator clock disagrees with the
// beacon by more than this is refused — even though both fields are
// signed individually, a wildly divergent pair signals a misbehaving
// operator clock.
//
// Default 5 minutes covers normal NTP drift but catches deliberate
// manipulation. Set core.Log.MaxClockSkew to 0 to disable.
const DefaultMaxClockSkew = 5 * 60 // seconds

// Checkpoint produces a fresh signed checkpoint and (if any witnesses are
// registered) gathers their countersignatures before persisting. The
// stored checkpoint thus always reflects the strongest evidence the
// operator could collect at signing time.
//
// Beacon, witness, and storage failures are handled differently:
//   - Beacon fetch failure: proceed without beacon (logged).
//   - Witness fetch failure: proceed with partial cosignature (logged).
//   - Storage failure: hard error; the checkpoint is not returned.
func (l *Log) Checkpoint() (*checkpoint.Checkpoint, error) {
	return l.CheckpointCtx(context.Background())
}

// CheckpointCtx is Checkpoint with a caller-supplied context (used to
// bound witness gather time).
func (l *Log) CheckpointCtx(ctx context.Context) (*checkpoint.Checkpoint, error) {
	ctx, span := obs.StartSpan(ctx, "stele.checkpoint")
	defer span.End()
	l.mu.Lock()
	root := l.tree.Root()
	head, err := l.store.HeadHash()
	if err != nil {
		l.mu.Unlock()
		return nil, err
	}
	size := l.tree.Size()
	l.mu.Unlock()

	var beacon *checkpoint.Beacon
	if l.beacon != nil {
		if b, ferr := l.beacon(); ferr == nil {
			beacon = b
		}
	}
	// Clock skew check: if we have a beacon round, the operator's
	// wall clock should agree with the beacon's expected time within
	// DefaultMaxClockSkew. drand mainnet ticks every 3 seconds from a
	// fixed genesis; converting Round -> wall-clock time and comparing
	// to time.Now() catches a deliberately-wrong operator clock.
	//
	// drand "default-unchained" parameters:
	//   GenesisTime: 1692489600 (2023-08-20T00:00:00Z UTC)
	//   Period: 3 seconds
	// These match the chain hash we ship as beacon.DefaultChainHash.
	if beacon != nil && beacon.Round > 0 && beacon.Source == "drand" {
		const drandGenesis = int64(1692489600)
		const drandPeriod = int64(3)
		expected := drandGenesis + drandPeriod*int64(beacon.Round)
		nowSec := time.Now().Unix()
		skew := nowSec - expected
		if skew < 0 {
			skew = -skew
		}
		if skew > int64(DefaultMaxClockSkew) {
			return nil, fmt.Errorf("core: refusing to checkpoint — operator clock disagrees with drand round %d by %ds (limit %ds)",
				beacon.Round, skew, DefaultMaxClockSkew)
		}
	}
	c, err := l.signer.Sign(size, root, head, beacon)
	if err != nil {
		obs.CheckpointsTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	// Gather witness signatures (best-effort).
	if _, gerr := l.GatherWitnessSignatures(ctx, c); gerr != nil {
		// Network-layer error; partial gathering is still useful so we
		// only return on hard failure (and there is none here — the call
		// already returned a status map).
		_ = gerr
	}
	body, err := c.Marshal()
	if err != nil {
		obs.CheckpointsTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	if err := l.store.SaveCheckpoint(c.Size, body); err != nil {
		obs.CheckpointsTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	obs.CheckpointsTotal.WithLabelValues("ok").Inc()
	return c, nil
}

// Rotate evolves the operator's signing key to a new epoch, irrevocably
// destroying the previous key. The next checkpoint will be signed by the
// new epoch.
func (l *Log) Rotate() error {
	_, err := l.signer.Rotate()
	if err != nil {
		obs.RotationsTotal.WithLabelValues("error").Inc()
		return err
	}
	obs.RotationsTotal.WithLabelValues("ok").Inc()
	obs.ActiveEpoch.Set(float64(l.signer.Chain().ActiveEpoch()))
	return nil
}

// LatestCheckpoint returns the most recent stored checkpoint, parsing it
// back into a struct.
func (l *Log) LatestCheckpoint() (*checkpoint.Checkpoint, error) {
	body, _, err := l.store.LatestCheckpoint()
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, nil
	}
	return checkpoint.Unmarshal(body)
}

// Anchor publishes the most recent checkpoint to every configured sink. The
// returned records map sink name -> Record; the joined error contains any
// per-sink failures.
func (l *Log) Anchor() (map[string]*anchor.Record, error) {
	_, span := obs.StartSpan(context.Background(), "stele.anchor")
	defer span.End()
	c, err := l.LatestCheckpoint()
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, errors.New("anchor: no checkpoint exists yet")
	}
	results := make(map[string]*anchor.Record, len(l.sinks))
	var errs []error
	for _, s := range l.sinks {
		rec, err := s.Publish(c)
		if err != nil {
			obs.AnchorWritesTotal.WithLabelValues(s.Name(), "error").Inc()
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		obs.AnchorWritesTotal.WithLabelValues(s.Name(), "ok").Inc()
		obs.MarkAnchorWrite()
		results[s.Name()] = rec
		body, err := serialiseAnchorRecord(rec)
		if err == nil {
			_ = l.store.SaveAnchor(c.Size, body)
		}
	}
	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}
	return results, nil
}

// CheckpointAndAnchor is the common operator workflow: sign a fresh
// checkpoint then push it to every sink.
func (l *Log) CheckpointAndAnchor() (*checkpoint.Checkpoint, map[string]*anchor.Record, error) {
	c, err := l.Checkpoint()
	if err != nil {
		return nil, nil, err
	}
	recs, err := l.Anchor()
	return c, recs, err
}
