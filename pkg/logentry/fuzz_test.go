package logentry

import (
	"encoding/json"
	"testing"
)

func FuzzEntryUnmarshal(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"index":0}`))
	f.Add([]byte(`{"index":1,"envelope":{"producer_id":"x"}}`))
	f.Add([]byte(`{"honeypot":true,"prev_hash":"!!!"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Unmarshal is the package-level helper; it can return error.
		e, err := Unmarshal(data)
		if err != nil {
			// Try the direct JSON path too — must also not panic.
			var raw Entry
			_ = json.Unmarshal(data, &raw)
			_ = raw.Canonical()
			return
		}
		// If Unmarshal returned a non-nil entry, the rest must not panic.
		_ = e.Canonical()
		_ = e.Verify()
	})
}
