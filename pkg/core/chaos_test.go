package core

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/storage"
)

// buildLogWithBeacon assembles a fresh Log + signer + sink in `dir`
// with the supplied beacon fetcher. Returns the Log; cleanup is
// handled via t.TempDir.
func buildLogWithBeacon(t *testing.T, fetcher CheckpointBeaconFetcher) *Log {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fws, err := fwdsec.NewSigner("chaos.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewSigner(fws)
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Options{
		Store:         st,
		Signer:        signer,
		Sinks:         []anchor.Sink{sink},
		BeaconFetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	// One real append so Checkpoint has something to commit.
	prod, err := attest.NewSoftwareAttestor("chaos-prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "chaos-prod",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	env, err := prod.Sign("chaos", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(env, false); err != nil {
		t.Fatal(err)
	}
	return l
}

// drandRoundFor returns the drand round that corresponds to a target
// wall-clock time, using the same chain parameters core.go checks
// against (genesis 1692489600, period 3s).
func drandRoundFor(target time.Time) uint64 {
	const drandGenesis = int64(1692489600)
	const drandPeriod = int64(3)
	round := (target.Unix() - drandGenesis) / drandPeriod
	if round < 1 {
		return 1
	}
	return uint64(round)
}

// TestChaos_ClockSkew_RefusesCheckpoint: simulate a beacon that
// reports a round corresponding to a time `skew` away from now. The
// operator must refuse to checkpoint with a clear error message.
//
// Cases tested:
//   - skew = +DefaultMaxClockSkew + 60s (operator clock too far ahead)
//   - skew = -DefaultMaxClockSkew - 60s (operator clock too far behind)
//   - skew = +DefaultMaxClockSkew - 60s (just inside tolerance — OK)
func TestChaos_ClockSkew_RefusesCheckpoint(t *testing.T) {
	cases := []struct {
		name      string
		skew      time.Duration
		wantError bool
	}{
		{"ahead_by_6m_rejects", +6 * time.Minute, true},
		{"behind_by_6m_rejects", -6 * time.Minute, true},
		{"ahead_by_4m_passes", +4 * time.Minute, false},
		{"in_sync_passes", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fetcher := func() (*checkpoint.Beacon, error) {
				// Pretend wall clock is `tc.skew` away from the beacon
				// round's "real" time. Easier: pick a round whose
				// "expected wall time" is now() - tc.skew, i.e. the
				// operator clock is `tc.skew` ahead/behind the beacon.
				targetRoundTime := time.Now().Add(-tc.skew)
				return &checkpoint.Beacon{
					Source: "drand",
					Round:  drandRoundFor(targetRoundTime),
				}, nil
			}
			l := buildLogWithBeacon(t, fetcher)
			_, err := l.Checkpoint()
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected clock-skew refusal at skew=%s, got nil", tc.skew)
				}
				if !strings.Contains(err.Error(), "clock") {
					t.Fatalf("expected error to mention clock, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("checkpoint should succeed at skew=%s, got: %v", tc.skew, err)
				}
			}
		})
	}
}

// TestChaos_NonDrandBeaconSkipsCheck: if the beacon source isn't
// "drand", the clock-skew comparison is skipped (different chains
// have different genesis times we don't know).
func TestChaos_NonDrandBeaconSkipsCheck(t *testing.T) {
	fetcher := func() (*checkpoint.Beacon, error) {
		// Source="local-test" — not drand. Round/genesis math is
		// meaningless here, and core must skip the check rather than
		// false-positive.
		return &checkpoint.Beacon{Source: "local-test", Round: 99999999}, nil
	}
	l := buildLogWithBeacon(t, fetcher)
	if _, err := l.Checkpoint(); err != nil {
		t.Fatalf("non-drand beacon should skip clock check, got error: %v", err)
	}
}

// TestChaos_BeaconUnreachable: when the beacon fetcher errors, the
// checkpoint must still succeed (beacon is optional / best-effort).
// The Beacon field on the resulting checkpoint will be nil.
func TestChaos_BeaconUnreachable(t *testing.T) {
	calls := 0
	fetcher := func() (*checkpoint.Beacon, error) {
		calls++
		return nil, context.DeadlineExceeded
	}
	l := buildLogWithBeacon(t, fetcher)
	c, err := l.Checkpoint()
	if err != nil {
		t.Fatalf("checkpoint should succeed with unreachable beacon: %v", err)
	}
	if c.Beacon != nil {
		t.Fatalf("checkpoint should carry no beacon when fetcher errored, got %+v", c.Beacon)
	}
	if calls == 0 {
		t.Fatal("fetcher should have been invoked")
	}
}
