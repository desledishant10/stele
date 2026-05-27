package threshold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Coordinator is the operator-side client that fans out a Sign request
// to every cosigner in a Group and collects MemberSigs until the
// threshold is reached.
//
// Network behaviour: each cosigner is contacted in parallel. A timeout
// per request prevents one slow cosigner from blocking the entire
// signing operation. As soon as `threshold` valid sigs arrive, the
// remaining requests are cancelled.
type Coordinator struct {
	Group      *Group
	HTTP       *http.Client
	CallerTag  string        // sent as X-Stele-Caller; empty disables the header
	Timeout    time.Duration // per-request timeout; default 10s
}

// NewCoordinator returns a Coordinator with sensible defaults.
func NewCoordinator(g *Group) *Coordinator {
	return &Coordinator{
		Group:   g,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		Timeout: 10 * time.Second,
	}
}

// Sign fans out and collects signatures. It returns when the threshold
// is met, all members responded, or ctx expires — whichever first.
// The returned []*MemberSig contains every valid signature it
// collected (which may exceed Threshold; verifiers will count up to
// the threshold).
func (c *Coordinator) Sign(ctx context.Context, msg []byte, contextLabel string) ([]*MemberSig, error) {
	if err := c.Group.Validate(); err != nil {
		return nil, err
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}

	type result struct {
		sig *MemberSig
		err error
	}
	resCh := make(chan result, len(c.Group.Members))

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, m := range c.Group.Members {
		if m.Endpoint == "" {
			continue
		}
		wg.Add(1)
		go func(m *Member) {
			defer wg.Done()
			sig, err := c.signOne(cctx, m, msg, contextLabel)
			resCh <- result{sig: sig, err: err}
		}(m)
	}
	go func() { wg.Wait(); close(resCh) }()

	var (
		gathered []*MemberSig
		errs     []error
	)
	for r := range resCh {
		if r.err != nil {
			errs = append(errs, r.err)
			continue
		}
		// Validate the returned sig before counting it. A faulty or
		// hostile cosigner cannot make us think we reached threshold
		// by returning bogus bytes.
		if err := r.sig.Verify(msg); err != nil {
			errs = append(errs, fmt.Errorf("member %s returned invalid sig: %w", r.sig.MemberID, err))
			continue
		}
		m := c.Group.MemberByID(r.sig.MemberID)
		if m == nil || !bytesEqual(m.PublicKey, r.sig.PublicKey) {
			errs = append(errs, fmt.Errorf("member %s returned mismatched public key", r.sig.MemberID))
			continue
		}
		gathered = append(gathered, r.sig)
		if uint32(len(gathered)) >= c.Group.Threshold {
			cancel() // got enough; tell remaining goroutines to stop
		}
	}

	if uint32(len(gathered)) < c.Group.Threshold {
		return gathered, fmt.Errorf("threshold not reached: %d/%d valid sigs (need %d); errors=%v",
			len(gathered), len(c.Group.Members), c.Group.Threshold, errs)
	}
	return gathered, nil
}

// signOne POSTs a signing request to one cosigner.
func (c *Coordinator) signOne(ctx context.Context, m *Member, msg []byte, label string) (*MemberSig, error) {
	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	body, err := json.Marshal(SignRequest{Message: msg, Context: label})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost,
		m.Endpoint+"/cosigner/v0/sign", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.CallerTag != "" {
		req.Header.Set("X-Stele-Caller", c.CallerTag)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cosigner %s: %w", m.ID, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("cosigner %s HTTP %d: %s", m.ID, resp.StatusCode, string(respBody))
	}
	var sr SignResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, err
	}
	if sr.Sig == nil {
		return nil, errors.New("cosigner returned nil sig")
	}
	return sr.Sig, nil
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
