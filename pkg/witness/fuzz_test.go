package witness

import (
	"encoding/json"
	"testing"
)

func FuzzSignedSeenUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"witness_id":"x","origin":"o","seen":{"5":"abc"}}`))
	f.Add([]byte(`{"seen":{"99999999999999999999":"x"}}`)) // overflow

	f.Fuzz(func(t *testing.T, data []byte) {
		var ss SignedSeen
		if err := json.Unmarshal(data, &ss); err != nil {
			return
		}
		_ = ss.Canonical()
		_ = ss.Verify()
	})
}

func FuzzCrossAttestationUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"attester_id":"a","peer_id":"b","origin":"o"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ca CrossAttestation
		if err := json.Unmarshal(data, &ca); err != nil {
			return
		}
		_ = ca.Canonical()
		_ = ca.Verify()
	})
}
