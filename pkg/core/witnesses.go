package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
	"github.com/desledishant10/stele/pkg/threshold"
	"github.com/desledishant10/stele/pkg/witness"
)

// thresholdGroup aliases the threshold.Group type so callers in this
// package can refer to it without an extra import where the receiver
// is just a pointer.
type thresholdGroup = threshold.Group

// RegisterWitness adds a witness to the operator's local list. The
// witness must already be running and exposing /witness/v0/cosign — the
// operator does not validate connectivity here, but the next checkpoint
// will reveal an unreachable witness via a missing cosig.
func (l *Log) RegisterWitness(w *storage.Witness) error {
	return l.store.RegisterWitness(w)
}

// ListWitnesses returns the witnesses configured for this operator.
func (l *Log) ListWitnesses() ([]*storage.Witness, error) {
	var out []*storage.Witness
	err := l.store.ListWitnesses(func(w *storage.Witness) error {
		out = append(out, w)
		return nil
	})
	return out, err
}

// GatherWitnessSignatures fans out to every registered witness and asks
// each to cosign `c`. Successful WitnessSigs are appended to c.Witnesses
// in place. The returned map summarises per-witness status for logging.
//
// A witness that fails (network error, fork detected, bad sig) is logged
// but does not abort the whole call — partial cosignature is normal in a
// real cohort. Callers requiring N-of-M can check len(c.Witnesses) on
// return.
func (l *Log) GatherWitnessSignatures(ctx context.Context, c *checkpoint.Checkpoint) (map[string]error, error) {
	ctx, span := obs.StartSpan(ctx, "stele.gather_witness_signatures")
	defer span.End()
	witnesses, err := l.ListWitnesses()
	if err != nil {
		return nil, err
	}
	if len(witnesses) == 0 {
		return map[string]error{}, nil
	}
	obs.SetAttrs(ctx, obs.AttrInt64("stele.witness.count", int64(len(witnesses))))
	chain := l.signer.Chain()
	group := l.signer.ThresholdGroup() // nil in single-sig mode

	type result struct {
		id  string
		sig *checkpoint.WitnessSig
		err error
	}
	resultCh := make(chan result, len(witnesses))
	var wg sync.WaitGroup
	for _, w := range witnesses {
		wg.Add(1)
		go func(w *storage.Witness) {
			defer wg.Done()
			wctx, wspan := obs.StartSpan(ctx, "stele.witness_cosign",
				obs.AttrString("stele.witness.id", w.ID))
			defer wspan.End()
			start := time.Now()
			sig, err := requestCosign(wctx, w, c, chain, group)
			obs.WitnessCosignDurationSeconds.WithLabelValues(w.ID).Observe(time.Since(start).Seconds())
			if err != nil {
				obs.SetAttrs(wctx, obs.AttrString("stele.witness.error", err.Error()))
			}
			resultCh <- result{id: w.ID, sig: sig, err: err}
		}(w)
	}
	wg.Wait()
	close(resultCh)

	status := make(map[string]error, len(witnesses))
	for r := range resultCh {
		if r.err != nil {
			obs.WitnessCosignTotal.WithLabelValues(r.id, "error").Inc()
			status[r.id] = r.err
			continue
		}
		// Validate sig against trusted witness public key (avoids accepting
		// a tampered response from a man-in-the-middle).
		if err := validateWitnessSig(c, r.sig, witnesses); err != nil {
			obs.WitnessCosignTotal.WithLabelValues(r.id, "rejected").Inc()
			status[r.id] = fmt.Errorf("returned sig invalid: %w", err)
			continue
		}
		obs.WitnessCosignTotal.WithLabelValues(r.id, "ok").Inc()
		c.Witnesses = append(c.Witnesses, r.sig)
		status[r.id] = nil
	}
	return status, nil
}

func requestCosign(ctx context.Context, w *storage.Witness, c *checkpoint.Checkpoint, chain *fwdsec.Chain, group *thresholdGroup) (*checkpoint.WitnessSig, error) {
	reqBody, err := json.Marshal(witness.CosignRequest{Checkpoint: c, Chain: chain, Group: group})
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, w.URL+"/witness/v0/cosign", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	obs.InjectHTTPHeaders(cctx, req.Header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	var cr witness.CosignResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, err
	}
	if cr.Sig == nil {
		return nil, errors.New("empty signature in response")
	}
	return cr.Sig, nil
}

func validateWitnessSig(c *checkpoint.Checkpoint, sig *checkpoint.WitnessSig, witnesses []*storage.Witness) error {
	var pub []byte
	for _, w := range witnesses {
		if w.ID == sig.WitnessID {
			pub = w.PublicKey
			break
		}
	}
	if pub == nil {
		return fmt.Errorf("unknown witness id %q", sig.WitnessID)
	}
	if !bytes.Equal(sig.PublicKey, pub) {
		return errors.New("witness returned a public key different from the one we trust")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), c.CanonicalForWitness(), sig.Signature) {
		return errors.New("witness signature does not verify")
	}
	return nil
}

