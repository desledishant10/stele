// Package watcher is the cross-checker that runs OUTSIDE the operator
// and the witness mesh. It fetches the latest checkpoint from the
// operator + every configured witness's signed view of that operator's
// log, and reports any divergence in the Merkle root at a given size.
//
// Why this exists. The protocol already has fork-detection inside the
// witness mesh (witnesses gossip with each other and refuse to keep
// cosigning a forked operator). The watcher is the BELT-AND-BRACES
// version: a separate process, on independent infrastructure, that
// neither the operator nor any single witness can suppress. Run it on
// a CI schedule, page the on-call on a non-zero exit code, and you
// have an alarm even if the witness gossip layer is compromised.
//
// The watcher does not require any trust in the operator. It compares:
//
//   - The operator's claimed latest checkpoint (`/api/v0/checkpoint`).
//   - Each witness's signed view of that same operator
//     (`/witness/v0/seen-signed?origin=...`).
//
// If at some size N two sources report different roots, that's a
// hard FORK. If a witness returns no view for size N, that's
// degraded but not a fork (witness may be behind). If the operator
// is unreachable, that's an operator outage, not a fork.
//
// Exit codes (per cmd/stele-watcher):
//
//	0  all consistent
//	1  divergence detected (real fork)
//	2  errors talking to one or more sources (no fork claim)
package watcher

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/desledishant10/stele/pkg/api"
	"github.com/desledishant10/stele/pkg/witness"
)

// Config configures one watcher run.
type Config struct {
	// Origin is the operator log's origin label (matches what
	// witnesses register their WatchedOperator with). Required.
	Origin string

	// OperatorURL is e.g. http://stele.example.com:8080. Required.
	OperatorURL string

	// WitnessURLs is one URL per witness, e.g.
	// http://witness-a.example.com:9090. Optional but the watcher is
	// only useful if at least two sources (operator + 1 witness)
	// are reachable.
	WitnessURLs []string

	// Timeout per HTTP call. Default 10s.
	Timeout time.Duration

	// HTTP, if set, overrides the default client. Used by tests to
	// inject a fake transport.
	HTTP *http.Client
}

// SourceView is one source's reported root at the size the operator
// claims as latest. Reachable=false means the source couldn't be
// contacted; ErrMessage records why.
type SourceView struct {
	Name        string `json:"name"`        // "operator" or witness URL
	Reachable   bool   `json:"reachable"`
	Size        uint64 `json:"size"`        // size we asked about
	RootHex     string `json:"root_hex"`    // hex(rootHash) at that size
	ErrMessage  string `json:"err,omitempty"`
}

// Report is the structured result of one Run.
type Report struct {
	Origin       string       `json:"origin"`
	At           time.Time    `json:"at"`
	OperatorView *SourceView  `json:"operator_view"`
	WitnessViews []*SourceView `json:"witness_views"`

	// Divergences is the set of (source, size, root) pairs that
	// disagree with the operator. Empty == consistent.
	Divergences []*Divergence `json:"divergences,omitempty"`
}

// Divergence captures one disagreement. By construction, OperatorRoot
// is always populated (we anchor on the operator's claimed root and
// compare); the divergent source's name + root identify the conflict.
type Divergence struct {
	Source       string `json:"source"`
	Size         uint64 `json:"size"`
	OperatorRoot string `json:"operator_root"`
	SourceRoot   string `json:"source_root"`
}

// Outcome categorises the run result. Distinct from divergences
// because callers need different exit codes for "fork detected" vs
// "couldn't reach the operator at all".
type Outcome string

const (
	OutcomeConsistent Outcome = "consistent"
	OutcomeDiverged   Outcome = "diverged"
	OutcomeErrored    Outcome = "errored"
)

// Run performs one cross-check pass. The Report is always populated
// (even on Errored) so the caller can persist it as audit evidence.
func Run(ctx context.Context, cfg Config) (*Report, Outcome, error) {
	if cfg.Origin == "" {
		return nil, OutcomeErrored, errors.New("watcher: Origin required")
	}
	if cfg.OperatorURL == "" {
		return nil, OutcomeErrored, errors.New("watcher: OperatorURL required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	rep := &Report{Origin: cfg.Origin, At: time.Now()}

	// 1. Ask the operator for its latest checkpoint. The size in this
	//    response anchors what we ask each witness about.
	opCkpt, err := fetchOperatorCheckpoint(ctx, client, cfg.OperatorURL)
	if err != nil {
		rep.OperatorView = &SourceView{
			Name:       "operator",
			Reachable:  false,
			ErrMessage: err.Error(),
		}
		// Can't ask witnesses meaningfully without the operator's
		// claim of "size N has root R" — still record what each
		// witness reports independently.
		rep.WitnessViews = fetchWitnessSeen(ctx, client, cfg.Origin, cfg.WitnessURLs)
		return rep, OutcomeErrored, nil
	}
	rep.OperatorView = &SourceView{
		Name:      "operator",
		Reachable: true,
		Size:      opCkpt.Size,
		RootHex:   hex.EncodeToString(opCkpt.RootHash),
	}

	// 2. For each witness, fetch its signed seen-map and look for an
	//    entry at the operator-claimed size.
	rep.WitnessViews = fetchWitnessSeenAtSize(ctx, client, cfg.Origin, opCkpt.Size, cfg.WitnessURLs)

	// 3. Compare.
	for _, wv := range rep.WitnessViews {
		if !wv.Reachable || wv.RootHex == "" {
			continue
		}
		if wv.RootHex != rep.OperatorView.RootHex {
			rep.Divergences = append(rep.Divergences, &Divergence{
				Source:       wv.Name,
				Size:         opCkpt.Size,
				OperatorRoot: rep.OperatorView.RootHex,
				SourceRoot:   wv.RootHex,
			})
		}
	}
	sort.SliceStable(rep.Divergences, func(i, j int) bool {
		return rep.Divergences[i].Source < rep.Divergences[j].Source
	})

	if len(rep.Divergences) > 0 {
		return rep, OutcomeDiverged, nil
	}
	// Edge case: every witness errored. We never confirmed
	// consistency — best to report Errored.
	allErrored := true
	for _, wv := range rep.WitnessViews {
		if wv.Reachable {
			allErrored = false
			break
		}
	}
	if allErrored && len(rep.WitnessViews) > 0 {
		return rep, OutcomeErrored, nil
	}
	return rep, OutcomeConsistent, nil
}

// --- HTTP fetchers ---

func fetchOperatorCheckpoint(ctx context.Context, c *http.Client, url string) (*ckptShape, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/v0/checkpoint", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("operator /checkpoint: HTTP %d: %s", resp.StatusCode, body)
	}
	var out api.CheckpointResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("operator /checkpoint: decode: %w", err)
	}
	if out.Checkpoint == nil {
		return nil, errors.New("operator returned no checkpoint")
	}
	return &ckptShape{Size: out.Checkpoint.Size, RootHash: out.Checkpoint.RootHash}, nil
}

// ckptShape is the subset of checkpoint.Checkpoint the watcher cares
// about. Keeping it local avoids a heavy import.
type ckptShape struct {
	Size     uint64
	RootHash []byte
}

func fetchWitnessSeenAtSize(ctx context.Context, c *http.Client, origin string, size uint64, urls []string) []*SourceView {
	out := make([]*SourceView, 0, len(urls))
	for _, u := range urls {
		sv := &SourceView{Name: u, Size: size}
		ss, err := fetchSignedSeen(ctx, c, u, origin)
		if err != nil {
			sv.ErrMessage = err.Error()
			out = append(out, sv)
			continue
		}
		sv.Reachable = true
		if hexRoot, ok := ss.Seen[size]; ok {
			sv.RootHex = hexRoot
		} else {
			sv.ErrMessage = fmt.Sprintf("witness has no view at size %d", size)
		}
		out = append(out, sv)
	}
	return out
}

// fetchWitnessSeen is the operator-unreachable variant: we still
// record each witness's signed seen map but can't pin it to a
// specific size. Useful for the Errored path so the report shows
// what was reachable.
func fetchWitnessSeen(ctx context.Context, c *http.Client, origin string, urls []string) []*SourceView {
	out := make([]*SourceView, 0, len(urls))
	for _, u := range urls {
		sv := &SourceView{Name: u}
		ss, err := fetchSignedSeen(ctx, c, u, origin)
		if err != nil {
			sv.ErrMessage = err.Error()
			out = append(out, sv)
			continue
		}
		sv.Reachable = true
		// No specific size to anchor on — record the highest size
		// the witness has seen, so report still shows useful state.
		var maxSize uint64
		var maxRoot string
		for sz, root := range ss.Seen {
			if sz >= maxSize {
				maxSize = sz
				maxRoot = root
			}
		}
		sv.Size = maxSize
		sv.RootHex = maxRoot
		out = append(out, sv)
	}
	return out
}

func fetchSignedSeen(ctx context.Context, c *http.Client, witnessURL, origin string) (*witness.SignedSeen, error) {
	url := witnessURL + "/witness/v0/seen-signed?origin=" + origin
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var out witness.SignedSeenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if out.Statement == nil {
		return nil, errors.New("witness returned no signed seen statement")
	}
	// Verify the signature so a man-in-the-middle can't lie.
	if err := out.Statement.Verify(); err != nil {
		return nil, fmt.Errorf("witness signed seen invalid: %w", err)
	}
	return out.Statement, nil
}
