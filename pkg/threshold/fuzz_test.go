package threshold

import (
	"encoding/json"
	"testing"
)

func FuzzGroupUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"origin":"o","threshold":1,"members":[{"id":"a","public_key":"AAAA"}]}`))
	f.Add([]byte(`{"version":99,"threshold":0,"members":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		g, err := Unmarshal(data)
		if err != nil {
			return // bad input rejected — fine
		}
		// If Unmarshal succeeded, the group is valid by contract.
		_ = g.Canonical()
		_ = g.Digest()
		_ = g.DigestHex()
		_ = g.RootMembers()
		// VerifyMulti against arbitrary garbage sigs must not panic.
		_ = VerifyMulti(g, []byte("test"), nil)
	})
}

// RootMembers is a small accessor helper added for the fuzz target — see group.go.
// (We can't fuzz private fields, so we exercise the public surface.)
func (g *Group) RootMembers() []*Member {
	out := make([]*Member, len(g.Members))
	copy(out, g.Members)
	return out
}

func FuzzMemberSigUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"member_id":"x","signature":"AAAA"}`))
	f.Add([]byte(`{"quantum_signature":"!!!"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var s MemberSig
		if err := json.Unmarshal(data, &s); err != nil {
			return
		}
		// Verify against arbitrary message — must not panic.
		_ = s.Verify([]byte("anything"))
	})
}
