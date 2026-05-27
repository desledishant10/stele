// Package beacon fetches a recent value from a public randomness beacon
// (drand by default) and packages it for inclusion in stele checkpoints.
//
// The point: the value produced by a beacon at round N is unpredictable
// before round N's time. So if a checkpoint contains the beacon's value
// for round N, that checkpoint provably did NOT exist before time(N).
// This defeats backdating attacks where a compromised operator tries to
// forge a checkpoint dated weeks ago.
//
// The drand network is operated by the League of Entropy and exposed via
// multiple public mirrors. We use the HTTP API; production deployments
// should additionally verify the BLS signature against the published
// drand group public key (a small dependency we omit for the MVP).
package beacon

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
)

// DefaultEndpoint is one of several public drand mirrors operated by the
// League of Entropy. The "default-unchained" chain has 3-second rounds.
const DefaultEndpoint = "https://api.drand.sh"

// DefaultChainHash is the SHA-256 of the default-unchained drand group
// public key, used as the chain identifier on the wire. Verifiers can
// validate they're seeing the same chain they expect.
const DefaultChainHash = "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce"

// Client fetches drand randomness rounds.
type Client struct {
	HTTP     *http.Client
	Endpoint string // e.g. "https://api.drand.sh"
	ChainHash string // hex; used in URL path
}

// New returns a Client pointing at the default drand endpoint.
func New() *Client {
	return &Client{
		HTTP:      &http.Client{Timeout: 10 * time.Second},
		Endpoint:  DefaultEndpoint,
		ChainHash: DefaultChainHash,
	}
}

type drandResponse struct {
	Round       uint64 `json:"round"`
	Randomness  string `json:"randomness"`
	Signature   string `json:"signature"`
	PreviousSig string `json:"previous_signature,omitempty"`
}

// Latest fetches the most recent randomness round and packages it for
// embedding in a checkpoint.
func (c *Client) Latest(ctx context.Context) (*checkpoint.Beacon, error) {
	url := fmt.Sprintf("%s/%s/public/latest", c.Endpoint, c.ChainHash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("beacon: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("beacon: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var dr drandResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return nil, fmt.Errorf("beacon: parse: %w", err)
	}
	if dr.Round == 0 || dr.Randomness == "" {
		return nil, errors.New("beacon: empty response")
	}
	rand, err := hex.DecodeString(dr.Randomness)
	if err != nil {
		return nil, fmt.Errorf("beacon: bad randomness hex: %w", err)
	}
	sig, _ := hex.DecodeString(dr.Signature)
	chainHash, _ := hex.DecodeString(c.ChainHash)
	return &checkpoint.Beacon{
		Source:    "drand",
		Round:     dr.Round,
		Value:     rand,
		Signature: sig,
		ChainHash: chainHash,
	}, nil
}

// FetcherFor returns a closure suitable for core.Options.BeaconFetcher.
// On failure it returns nil and the error — callers (e.g. core.Log) may
// choose to proceed without a beacon rather than block checkpointing.
func (c *Client) FetcherFor(ctx context.Context) func() (*checkpoint.Beacon, error) {
	return func() (*checkpoint.Beacon, error) {
		// Use a per-call timeout so a slow beacon never blocks a
		// checkpoint scheduler tick for long.
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return c.Latest(cctx)
	}
}
