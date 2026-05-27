package readlog

import (
	"encoding/json"
	"testing"
)

func FuzzEventUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"index":0,"entry_idx":0}`))
	f.Add([]byte(`{"event_hash":"!!!"}`))
	f.Add([]byte(`{"signature":"AAAA","quantum_signature":"BBBB"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ev Event
		if err := json.Unmarshal(data, &ev); err != nil {
			return
		}
		_ = ev.Canonical()
		_ = ev.Verify()
	})
}
