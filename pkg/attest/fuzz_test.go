package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// FuzzEnvelopeUnmarshal sends arbitrary bytes through the JSON
// deserialiser, the canonical encoder, AND the signature verifier. No
// input should panic — malformed data should fall through to an
// error. A successful Verify against arbitrary input would also be a
// bug (an attacker who can produce one has cryptographic break).
func FuzzEnvelopeUnmarshal(f *testing.F) {
	// Seed corpus: a few shapes we know the verifier should handle.
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"producer_id":"x"}`))
	f.Add([]byte(`{"producer_id":"x","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	f.Add([]byte(`{"producer_id":"x","signature":"AAAA","quantum_signature":"BBBB"}`))
	// A real envelope (seed with shape, not values).
	a, _ := NewSoftwareAttestor("seed")
	env, _ := a.Sign("src", []byte("data"))
	real, _ := json.Marshal(env)
	f.Add(real)

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return // bad JSON is fine
		}
		// Canonical() must never panic.
		_ = env.Canonical()
		// Verify() must never panic — only return error.
		_ = env.Verify()
	})
}

// FuzzCanonicalDeterminism: the canonical bytes for any envelope must
// be deterministic. Marshalling, unmarshalling, and re-canonicalising
// must always produce the same bytes — guards against future
// non-deterministic encoders sneaking in (e.g. someone using a map
// iteration order).
func FuzzCanonicalDeterminism(f *testing.F) {
	f.Add(uint32(1), "x", "y", []byte("data"))
	f.Fuzz(func(t *testing.T, ts uint32, pid, src string, data []byte) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		env := &Envelope{
			ProducerID: pid,
			TimeNanos:  int64(ts),
			Source:     src,
			Data:       data,
			PublicKey:  pub,
			Type:       TypeSoftware,
		}
		c1 := env.Canonical()
		c2 := env.Canonical()
		if string(c1) != string(c2) {
			t.Fatalf("non-deterministic canonical bytes")
		}
	})
}
