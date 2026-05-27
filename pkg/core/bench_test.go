package core

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/storage"
)

type benchRig struct {
	log      *Log
	producer *attest.SoftwareAttestor
	store    *storage.Store
}

func newBenchRig(b *testing.B) *benchRig {
	b.Helper()
	dir := b.TempDir()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		b.Fatal(err)
	}
	fws, err := fwdsec.NewSigner("bench.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		b.Fatal(err)
	}
	signer := checkpoint.NewSigner(fws)
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		b.Fatal(err)
	}
	l, err := New(context.Background(), Options{
		Store:  st,
		Signer: signer,
		Sinks:  []anchor.Sink{sink},
	})
	if err != nil {
		b.Fatal(err)
	}
	prod, err := attest.NewSoftwareAttestor("bench-producer")
	if err != nil {
		b.Fatal(err)
	}
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "bench-producer",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	return &benchRig{log: l, producer: prod, store: st}
}

// End-to-end append: attest -> hash chain -> badger write -> merkle.
// This is the throughput number that matters for capacity planning.
func BenchmarkLogAppend(b *testing.B) {
	r := newBenchRig(b)
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		env, err := r.producer.Sign("bench-src", payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := r.log.Append(env, false); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "entries/sec")
}

// Producer-side attestation cost (Ed25519 sign + canonical encoding).
// Isolated so we can tell whether a regression is in signing or in storage.
func BenchmarkProducerSign(b *testing.B) {
	prod, err := attest.NewSoftwareAttestor("bench-producer")
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := prod.Sign("bench-src", payload); err != nil {
			b.Fatal(err)
		}
	}
}
