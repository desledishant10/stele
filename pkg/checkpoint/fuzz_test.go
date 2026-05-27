package checkpoint

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// FuzzCheckpointUnmarshal validates that hostile JSON cannot crash the
// checkpoint parser or verifier. A signature-bypass would also be a
// cryptographic break.
func FuzzCheckpointUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"size":0}`))
	f.Add([]byte(`{"size":18446744073709551615}`)) // max uint64
	f.Add([]byte(`{"witnesses":[{}]}`))
	f.Add([]byte(`{"member_sigs":[{}]}`))
	f.Add([]byte(`{"signature":"!!!"}`)) // bad base64
	f.Add([]byte(`{"quantum_signature":"AAAA"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c Checkpoint
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		_ = c.Canonical()
		_ = c.CanonicalForWitness()
		// Verify without chain — should error, not panic.
		_ = Verify(&c, nil, ed25519.PublicKey{}, nil)
	})
}
