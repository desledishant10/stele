// Package audit is the data-collection layer the `stele audit`
// command uses. It calls the operator's read-only HTTP API,
// cross-checks against witnesses (if any), and assembles a
// structured Report the renderers (text, JSON, PDF) consume.
//
// audit is intentionally pure: it never mutates server state. The
// auditor can run it as often as they like without affecting the
// operator. The only side effects are HTTP requests and, optionally,
// a DNSSEC lookup for the trust anchor.
package audit

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/merkle"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/threshold"
	"github.com/desledishant10/stele/pkg/verify"
)

// Config configures one audit run.
type Config struct {
	// OperatorURL is the operator the auditor is auditing. Required.
	OperatorURL string

	// RootPublicKey is the trust anchor. The auditor obtained it
	// out of band (paper, DNSSEC, prior release, etc.). If empty,
	// the auditor is "blindly trusting whatever the server says is
	// the root" — useful for quick smoke audits, NOT for compliance
	// evidence. The Report flags this in TrustAnchorSource.
	RootPublicKey ed25519.PublicKey

	// TrustAnchorSource describes how the caller obtained
	// RootPublicKey — "dnssec" / "paper" / "ca-bundle" / "self-fetched"
	// / "" (unverified). Recorded verbatim in the Report for the
	// compliance reader.
	TrustAnchorSource string

	// Producers, if non-nil, restricts inclusion-proof sampling to
	// these IDs. Empty list = no sampling. The default is to verify
	// inclusion of `SampleN` entries chosen uniformly at random.
	Producers []string

	// SampleN is how many entries to fetch + inclusion-verify. 0
	// disables sampling. Larger values give stronger but slower
	// evidence. 10 is a reasonable default.
	SampleN int

	// Timeout per HTTP call. Default 15s.
	Timeout time.Duration

	// HTTP overrides the default client. Used by tests.
	HTTP *http.Client
}

// Report is the structured result of one audit. Designed to be
// rendered as plain text (CLI), JSON (machine-readable), or PDF
// (compliance deliverable).
type Report struct {
	// Identity of the log being audited.
	OperatorURL string    `json:"operator_url"`
	Origin      string    `json:"origin"`
	Size        uint64    `json:"size"`
	AuditTime   time.Time `json:"audit_time"`

	// Trust anchor verification.
	TrustAnchor TrustAnchorSummary `json:"trust_anchor"`

	// Chain integrity: every epoch verified.
	Chain ChainSummary `json:"chain"`

	// Latest checkpoint + witness cosignatures.
	LatestCheckpoint CheckpointSummary `json:"latest_checkpoint"`

	// External anchor sources we found evidence of.
	Anchors []AnchorSummary `json:"anchors,omitempty"`

	// Inclusion-proof sample.
	Samples []InclusionSample `json:"samples,omitempty"`

	// Top-level pass/fail. PASS means every check returned no error.
	Status     Status   `json:"status"`
	Findings   []string `json:"findings,omitempty"`   // human-readable issues
}

// TrustAnchorSummary describes how the auditor obtained + verified
// the root pubkey.
type TrustAnchorSummary struct {
	Source            string `json:"source"`               // "paper", "dnssec", "ca-bundle", "self-fetched", ""
	RootPublicKeyHex  string `json:"root_public_key_hex"`
	RootKeyID         string `json:"root_key_id"`          // first 8 bytes of SHA-256(pubkey), hex
	MatchedOnServer   bool   `json:"matched_on_server"`    // true iff server-reported root == caller-supplied root
	Notes             string `json:"notes,omitempty"`
}

// ChainSummary describes the full forward-secure rotation chain.
type ChainSummary struct {
	Origin       string         `json:"origin"`
	ActiveEpoch  uint64         `json:"active_epoch"`
	Epochs       int            `json:"epochs"`
	Verified     bool           `json:"verified"`
	VerifyError  string         `json:"verify_error,omitempty"`
	EpochSummary []EpochSummary `json:"epoch_summary"`
}

// EpochSummary is one entry per rotation cert.
type EpochSummary struct {
	Epoch     uint64 `json:"epoch"`
	StartedAt int64  `json:"started_at"`
	KeyID     string `json:"key_id"`
	Hybrid    bool   `json:"hybrid"`
	Threshold bool   `json:"threshold"`
}

// CheckpointSummary describes the latest committed checkpoint.
type CheckpointSummary struct {
	Size              uint64       `json:"size"`
	RootHashHex       string       `json:"root_hash_hex"`
	SignedAt          time.Time    `json:"signed_at"`
	Epoch             uint64       `json:"epoch"`
	Verified          bool         `json:"verified"`
	VerifyError       string       `json:"verify_error,omitempty"`
	BeaconBound       bool         `json:"beacon_bound"`
	BeaconSource      string       `json:"beacon_source,omitempty"`
	WitnessCount      int          `json:"witness_count"`
	Witnesses         []WitnessSig `json:"witnesses,omitempty"`
	ThresholdMode     bool         `json:"threshold_mode"`
	ThresholdRequired uint32       `json:"threshold_required,omitempty"`
	ThresholdActual   int          `json:"threshold_actual,omitempty"`
	HybridSigned      bool         `json:"hybrid_signed"`
}

// WitnessSig is one witness's countersignature.
type WitnessSig struct {
	WitnessID string `json:"witness_id"`
	KeyID     string `json:"key_id"`
}

// AnchorSummary is one external anchoring source we found.
type AnchorSummary struct {
	Sink string `json:"sink"`
	URL  string `json:"url,omitempty"`
	Note string `json:"note,omitempty"`
}

// InclusionSample is one entry's inclusion proof verification.
type InclusionSample struct {
	Index    uint64 `json:"index"`
	Verified bool   `json:"verified"`
	Producer string `json:"producer"`
	Error    string `json:"error,omitempty"`
}

// Status is the overall audit verdict.
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
)

// Run performs one audit pass. The Report is always populated, even
// on failures, so the caller can render evidence regardless.
func Run(ctx context.Context, cfg Config) (*Report, error) {
	if cfg.OperatorURL == "" {
		return nil, errors.New("audit: OperatorURL required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}

	rep := &Report{
		OperatorURL: cfg.OperatorURL,
		AuditTime:   time.Now().UTC(),
		Status:      StatusPass,
	}

	// 1. Fetch operator pubkey + chain.
	var pk api.PubKeyResponse
	if err := httpGet(ctx, client, cfg.OperatorURL+"/api/v0/pubkey", &pk); err != nil {
		rep.Status = StatusFail
		rep.Findings = append(rep.Findings, "failed to fetch /pubkey: "+err.Error())
		return rep, nil
	}
	rep.Origin = pk.Origin

	// 2. Trust anchor.
	rep.TrustAnchor = checkTrustAnchor(cfg, pk.RootPublicKey)
	if !rep.TrustAnchor.MatchedOnServer && cfg.TrustAnchorSource != "" {
		rep.Status = StatusFail
		rep.Findings = append(rep.Findings,
			"trust anchor mismatch: server's claimed root does not match the caller-supplied root anchor")
	}
	if cfg.TrustAnchorSource == "" {
		rep.Status = pickStatus(rep.Status, StatusWarn)
		rep.Findings = append(rep.Findings,
			"trust-anchor source unspecified — running in 'trust whatever server reports' mode (NOT compliance-grade)")
	}

	// 3. Chain verification.
	var chainResp api.KeyChainResponse
	if err := httpGet(ctx, client, cfg.OperatorURL+"/api/v0/keychain", &chainResp); err != nil {
		rep.Chain = ChainSummary{VerifyError: err.Error()}
		rep.Status = StatusFail
		rep.Findings = append(rep.Findings, "failed to fetch /keychain: "+err.Error())
	} else {
		rep.Chain = summarizeChain(chainResp.Chain, pk.RootPublicKey)
		if !rep.Chain.Verified {
			rep.Status = StatusFail
			rep.Findings = append(rep.Findings, "chain verification failed: "+rep.Chain.VerifyError)
		}
	}

	// 4. Latest checkpoint.
	var ckpt api.CheckpointResponse
	if err := httpGet(ctx, client, cfg.OperatorURL+"/api/v0/checkpoint", &ckpt); err != nil {
		rep.LatestCheckpoint = CheckpointSummary{VerifyError: err.Error()}
		rep.Status = StatusFail
		rep.Findings = append(rep.Findings, "failed to fetch /checkpoint: "+err.Error())
	} else if ckpt.Checkpoint == nil {
		rep.Status = pickStatus(rep.Status, StatusWarn)
		rep.Findings = append(rep.Findings, "operator has no checkpoint yet")
	} else {
		v := &verify.Verifier{
			Origin:        pk.Origin,
			RootPublicKey: pk.RootPublicKey,
			Chain:         chainResp.Chain,
		}
		rep.LatestCheckpoint = summarizeCheckpoint(ckpt.Checkpoint, v)
		rep.Size = ckpt.Checkpoint.Size
		if !rep.LatestCheckpoint.Verified {
			rep.Status = StatusFail
			rep.Findings = append(rep.Findings,
				"checkpoint signature verification failed: "+rep.LatestCheckpoint.VerifyError)
		}
	}

	// 5. /size (sanity cross-check between checkpoint and current size).
	var size api.SizeResponse
	if err := httpGet(ctx, client, cfg.OperatorURL+"/api/v0/size", &size); err == nil {
		if rep.LatestCheckpoint.Size > 0 && size.Size < rep.LatestCheckpoint.Size {
			rep.Status = StatusFail
			rep.Findings = append(rep.Findings,
				fmt.Sprintf("size regression: /size reports %d but latest checkpoint is at size %d",
					size.Size, rep.LatestCheckpoint.Size))
		}
	}

	// 6. Inclusion-proof sample.
	if cfg.SampleN > 0 && rep.LatestCheckpoint.Size > 0 {
		rep.Samples = sampleInclusion(ctx, client, cfg, rep.LatestCheckpoint.Size, ckpt.Checkpoint)
		for _, s := range rep.Samples {
			if !s.Verified {
				rep.Status = StatusFail
				rep.Findings = append(rep.Findings,
					fmt.Sprintf("inclusion proof failed for entry %d: %s", s.Index, s.Error))
			}
		}
	}

	return rep, nil
}

// --- helpers ---

func httpGet(ctx context.Context, c *http.Client, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func pickStatus(current, candidate Status) Status {
	if current == StatusFail || candidate == StatusFail {
		return StatusFail
	}
	if current == StatusWarn || candidate == StatusWarn {
		return StatusWarn
	}
	return StatusPass
}

func checkTrustAnchor(cfg Config, serverRoot ed25519.PublicKey) TrustAnchorSummary {
	out := TrustAnchorSummary{
		Source:           cfg.TrustAnchorSource,
		RootPublicKeyHex: hex.EncodeToString(serverRoot),
		RootKeyID:        fwdsec.KeyID(serverRoot),
	}
	if cfg.RootPublicKey == nil {
		out.Notes = "no pre-shared trust anchor supplied; server-reported root is unchecked"
		return out
	}
	out.MatchedOnServer = bytesEqual(cfg.RootPublicKey, serverRoot)
	if !out.MatchedOnServer {
		out.Notes = "mismatch — operator-reported root does NOT match the trust anchor"
	}
	return out
}

func summarizeChain(chain *fwdsec.Chain, root ed25519.PublicKey) ChainSummary {
	out := ChainSummary{}
	if chain == nil {
		out.VerifyError = "chain not returned by server"
		return out
	}
	out.Origin = chain.Origin
	out.ActiveEpoch = chain.ActiveEpoch()
	out.Epochs = len(chain.Certs)
	if err := chain.VerifyChain(root); err != nil {
		out.VerifyError = err.Error()
		return out
	}
	out.Verified = true
	for _, c := range chain.Certs {
		out.EpochSummary = append(out.EpochSummary, EpochSummary{
			Epoch:     c.Epoch,
			StartedAt: c.StartedAt,
			KeyID:     fwdsec.KeyID(c.PublicKey),
			Hybrid:    len(c.QuantumPublicKey) > 0,
			Threshold: len(c.MemberSigs) > 0,
		})
	}
	return out
}

func summarizeCheckpoint(c *checkpoint.Checkpoint, v *verify.Verifier) CheckpointSummary {
	out := CheckpointSummary{
		Size:        c.Size,
		RootHashHex: hex.EncodeToString(c.RootHash),
		SignedAt:    time.Unix(0, c.TimeNanos),
		Epoch:       c.EpochIdx,
		WitnessCount: len(c.Witnesses),
		ThresholdMode: c.ThresholdGroupDigest != "",
		HybridSigned:  len(c.QuantumSignature) > 0,
	}
	if c.Beacon != nil {
		out.BeaconBound = true
		out.BeaconSource = c.Beacon.Source
	}
	if c.ThresholdGroupDigest != "" {
		out.ThresholdActual = len(c.MemberSigs)
	}
	for _, w := range c.Witnesses {
		out.Witnesses = append(out.Witnesses, WitnessSig{
			WitnessID: w.WitnessID,
			KeyID:     fwdsec.KeyID(w.PublicKey),
		})
	}
	if v != nil {
		if err := v.Checkpoint(c); err != nil {
			out.VerifyError = err.Error()
			return out
		}
	}
	out.Verified = true
	return out
}

func sampleInclusion(ctx context.Context, client *http.Client, cfg Config, size uint64, ckpt *checkpoint.Checkpoint) []InclusionSample {
	n := cfg.SampleN
	if n > int(size) {
		n = int(size)
	}
	// Deterministic sampling: evenly-spaced indices 0..size-1.
	// Predictable, easy to re-run, and covers the full range.
	out := make([]InclusionSample, 0, n)
	step := size / uint64(n)
	if step == 0 {
		step = 1
	}
	for i := uint64(0); i < size && len(out) < n; i += step {
		sample := InclusionSample{Index: i}
		var entryResp struct {
			Entry struct {
				Index    uint64 `json:"index"`
				LeafHash []byte `json:"leaf_hash"`
				Envelope struct {
					ProducerID string `json:"producer_id"`
				} `json:"envelope"`
			} `json:"entry"`
		}
		entryURL := fmt.Sprintf("%s/api/v0/entries/%d", cfg.OperatorURL, i)
		if err := httpGet(ctx, client, entryURL, &entryResp); err != nil {
			sample.Error = "fetch entry: " + err.Error()
			out = append(out, sample)
			continue
		}
		sample.Producer = entryResp.Entry.Envelope.ProducerID

		var proofResp api.InclusionProofResponse
		proofURL := fmt.Sprintf("%s/api/v0/proof/inclusion?index=%d&tree_size=%d", cfg.OperatorURL, i, size)
		if err := httpGet(ctx, client, proofURL, &proofResp); err != nil {
			sample.Error = "fetch proof: " + err.Error()
			out = append(out, sample)
			continue
		}
		if err := merkle.VerifyInclusion(i, size, entryResp.Entry.LeafHash, proofResp.Proof, ckpt.RootHash); err != nil {
			sample.Error = err.Error()
			out = append(out, sample)
			continue
		}
		sample.Verified = true
		out = append(out, sample)
	}
	return out
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

// unused but kept for symmetry with the pdf/json renderers' import surface
var _ = storage.Producer{}
var _ = threshold.MemberSig{}
