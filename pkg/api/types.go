// Package api defines the HTTP wire format and handlers for the
// provenance log. All responses are JSON; binary fields are base64-encoded
// (Go's default behaviour for []byte in encoding/json).
package api

import (
	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/threshold"
)

const APIVersion = "v0"

// AppendRequest is the body of POST /api/v0/append. The Envelope must be
// pre-signed by a registered producer.
type AppendRequest struct {
	Envelope *attest.Envelope `json:"envelope"`
	Honeypot bool             `json:"honeypot,omitempty"`
}

// RegisterProducerRequest is the body of POST /api/v0/producers.
type RegisterProducerRequest struct {
	Producer *storage.Producer `json:"producer"`
}

// ListProducersResponse is the body of GET /api/v0/producers.
type ListProducersResponse struct {
	Producers []*storage.Producer `json:"producers"`
}

// EnrollmentRequest is the body of POST /api/v0/enrollments. The
// operator (steled) mints a signed enrollment from these fields using
// its active chain key and returns the signed Producer record.
type EnrollmentRequest struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	AttestationType  string `json:"attestation_type"`
	Description      string `json:"description,omitempty"`
	Scope            string `json:"scope,omitempty"`
	// ValiditySeconds is how long the enrollment is good for. 0 means
	// "never expires until revoked". Avoid passing absolute timestamps
	// — clock drift between caller and operator would silently change
	// expiry.
	ValiditySeconds int64 `json:"validity_seconds,omitempty"`
}

// EnrollmentResponse wraps the signed Producer record. Callers should
// ship this to the producer-operator team for storage alongside the
// producer's private key.
type EnrollmentResponse struct {
	Producer *storage.Producer `json:"producer"`
}

// BeginEnrollmentRequest is the body of POST /enrollments/begin. The
// server returns a challenge the producer must sign with their private
// key (proof of possession). Fields are the same as EnrollmentRequest
// EXCEPT the server picks the OperatorEpoch and IssuedAt itself, and
// they're baked into the returned challenge.
type BeginEnrollmentRequest struct {
	ID               string `json:"id"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	AttestationType  string `json:"attestation_type"`
	Description      string `json:"description,omitempty"`
	Scope            string `json:"scope,omitempty"`
	ValiditySeconds  int64  `json:"validity_seconds,omitempty"`
}

// BeginEnrollmentResponse carries the challenge the producer signs.
type BeginEnrollmentResponse struct {
	ChallengeID    string `json:"challenge_id"`
	ChallengeBytes []byte `json:"challenge_bytes"`
	// ExpiresAtNS is the absolute UnixNano time after which the
	// challenge will be rejected.
	ExpiresAtNS int64 `json:"expires_at_ns"`
}

// ConfirmEnrollmentRequest is the body of POST /enrollments/confirm.
// ChallengeID identifies the pending state from begin; Signature is
// the producer's Ed25519 signature over ChallengeBytes. In hybrid
// mode QuantumSignature is also required.
type ConfirmEnrollmentRequest struct {
	ChallengeID      string `json:"challenge_id"`
	Signature        []byte `json:"signature"`
	QuantumSignature []byte `json:"quantum_signature,omitempty"`
}

// RevokeProducerRequest is the body of POST /api/v0/producers/revoke.
// `Reason` is recorded into the admin audit log and the producer
// record itself.
type RevokeProducerRequest struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// RegisterWitnessRequest is the body of POST /api/v0/witnesses.
type RegisterWitnessRequest struct {
	Witness *storage.Witness `json:"witness"`
}

// ListWitnessesResponse is the body of GET /api/v0/witnesses.
type ListWitnessesResponse struct {
	Witnesses []*storage.Witness `json:"witnesses"`
}

// AppendResponse is the body returned by POST /api/v0/append.
type AppendResponse struct {
	Entry *logentry.Entry `json:"entry"`
}

// EntryResponse wraps a single entry.
type EntryResponse struct {
	Entry *logentry.Entry `json:"entry"`
}

// EntriesResponse wraps a range of entries.
type EntriesResponse struct {
	Entries []*logentry.Entry `json:"entries"`
	From    uint64            `json:"from"`
	To      uint64            `json:"to"`
}

// SizeResponse reports the current tree size.
type SizeResponse struct {
	Size     uint64 `json:"size"`
	RootHash []byte `json:"root_hash"`
	HeadHash []byte `json:"head_hash"`
}

// CheckpointResponse wraps the most recent signed checkpoint.
type CheckpointResponse struct {
	Checkpoint *checkpoint.Checkpoint `json:"checkpoint"`
}

// InclusionProofResponse is the answer to GET /api/v0/proof/inclusion.
type InclusionProofResponse struct {
	Index    uint64   `json:"index"`
	TreeSize uint64   `json:"tree_size"`
	LeafHash []byte   `json:"leaf_hash"`
	Proof    [][]byte `json:"proof"`
	RootHash []byte   `json:"root_hash"`
}

// ConsistencyProofResponse is the answer to GET /api/v0/proof/consistency.
type ConsistencyProofResponse struct {
	OldSize uint64   `json:"old_size"`
	NewSize uint64   `json:"new_size"`
	OldRoot []byte   `json:"old_root"`
	NewRoot []byte   `json:"new_root"`
	Proof   [][]byte `json:"proof"`
}

// AnchorResponse reports the result of POST /api/v0/anchor.
type AnchorResponse struct {
	Records map[string]*anchor.Record `json:"records"`
}

// PubKeyResponse advertises the operator's identity plus the forward-secure
// rotation chain. Verifiers anchor trust on RootPublicKey (the genesis
// epoch), then walk the chain to find the public key for any specific
// checkpoint's EpochIdx.
type PubKeyResponse struct {
	Origin        string `json:"origin"`
	RootPublicKey []byte `json:"root_public_key"` // genesis epoch (trust anchor)
	ActiveEpoch   uint64 `json:"active_epoch"`
	ActiveKeyID   string `json:"active_key_id"`
}

// KeyChainResponse returns the full forward-secure rotation chain.
type KeyChainResponse struct {
	Chain *fwdsec.Chain `json:"chain"`
}

// ThresholdGroupResponse exposes the operator's currently-active
// threshold signing group (nil if running in single-sig mode).
type ThresholdGroupResponse struct {
	Group *threshold.Group `json:"group"`
}

// ErrorResponse is returned for any 4xx/5xx.
type ErrorResponse struct {
	Error string `json:"error"`
}
