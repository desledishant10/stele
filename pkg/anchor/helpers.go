package anchor

import (
	"encoding/base64"
	"os"
	"path/filepath"
)

func base64Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}

// appendLine atomically appends a single line to a file. Used by sinks
// when they need a durable trail of payloads (e.g. fallback log).
func appendLine(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
