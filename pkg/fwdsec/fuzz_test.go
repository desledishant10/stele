package fwdsec

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func FuzzRotationCertUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"epoch":0}`))
	f.Add([]byte(`{"signed_by":"AAA"}`))
	f.Add([]byte(`{"quantum_signature":"BBB"}`))
	f.Add([]byte(`{"member_sigs":[{},{}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var c RotationCert
		if err := json.Unmarshal(data, &c); err != nil {
			return
		}
		_ = c.Canonical()
		_ = c.Verify()
	})
}

func FuzzChainUnmarshal(f *testing.F) {
	f.Add([]byte(`{"origin":"x","certs":[]}`))
	f.Add([]byte(`{"origin":"x","certs":[{"epoch":0}]}`))
	f.Add([]byte(`{"origin":"x","active_locator":"","certs":[{"epoch":0,"public_key":"AAAA"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var chain Chain
		if err := json.Unmarshal(data, &chain); err != nil {
			return
		}
		_ = chain.RootPublicKey()
		_ = chain.ActivePublicKey()
		_ = chain.ActiveEpoch()
		// VerifyChain with a fake root — must error gracefully on garbage.
		fakeRoot := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		_ = chain.VerifyChain(fakeRoot)
	})
}
