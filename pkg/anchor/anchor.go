// Package anchor publishes signed checkpoints to external sinks. Once a
// checkpoint is anchored to a sink the log operator does not control, the
// entire log history below that checkpoint becomes effectively immutable:
// to rewrite history the operator would have to also tamper with every
// sink that holds the prior anchor.
//
// The MVP ships with a single file-based sink that writes append-only JSON
// lines. The Sink interface is small on purpose so production deployments
// can add additional backends (Sigstore Rekor, Bitcoin via OpenTimestamps,
// independent witness signers, S3 with object lock, etc.) without changing
// the rest of the system.
package anchor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
)

// Record is what gets written to a sink. It wraps the signed checkpoint with
// sink-specific metadata so verifiers can recover the original document.
type Record struct {
	Checkpoint   *checkpoint.Checkpoint `json:"checkpoint"`
	SinkName     string                 `json:"sink_name"`
	SinkRef      string                 `json:"sink_ref"`     // e.g. file offset, Rekor UUID
	AnchoredAt   int64                  `json:"anchored_at"`  // unix nano
	RecordHash   string                 `json:"record_hash"`  // SHA-256 of canonical checkpoint
}

// Sink accepts signed checkpoints and stores them somewhere durable.
// Implementations should be safe for concurrent use.
type Sink interface {
	Name() string
	Publish(c *checkpoint.Checkpoint) (*Record, error)
}

// FileSink writes one JSON-encoded Record per line into an append-only file.
// The file is opened in append mode and fsynced after every write so a crash
// after Publish() cannot lose the anchor.
//
// To make tampering observable, the sink also maintains a separate "head"
// file that just contains the most recent line's SHA-256. A monitor process
// can sync that single hash to a different host cheaply.
type FileSink struct {
	path     string
	headPath string
	mu       sync.Mutex
}

// NewFileSink opens or creates an append-only anchor log at `path`.
func NewFileSink(path string) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	// Touch the file so subsequent Stat / append calls succeed.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return &FileSink{path: path, headPath: path + ".head"}, nil
}

// Name implements Sink.
func (s *FileSink) Name() string { return "file:" + s.path }

// Publish writes the record. It returns a Record with SinkRef set to the
// byte offset the line was written at, which is enough for auditors to seek
// directly to it.
func (s *FileSink) Publish(c *checkpoint.Checkpoint) (*Record, error) {
	if c == nil || c.Signature == nil {
		return nil, errors.New("anchor: refusing to publish unsigned checkpoint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	offset, err := f.Seek(0, 2)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(c.Canonical())
	rec := &Record{
		Checkpoint: c,
		SinkName:   s.Name(),
		SinkRef:    fmt.Sprintf("offset=%d", offset),
		AnchoredAt: time.Now().UnixNano(),
		RecordHash: hex.EncodeToString(sum[:]),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	// Update head pointer atomically (write to tmp, rename).
	tmp := s.headPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(rec.RecordHash+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, s.headPath); err != nil {
		return nil, err
	}
	return rec, nil
}

// ReadAll loads every Record from the sink in write order. Used by the
// auditor / verifier to walk the anchor history.
func (s *FileSink) ReadAll() ([]*Record, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var (
		out  []*Record
		line []byte
	)
	for _, b := range data {
		if b == '\n' {
			if len(line) > 0 {
				var r Record
				if err := json.Unmarshal(line, &r); err != nil {
					return nil, fmt.Errorf("anchor: malformed record: %w", err)
				}
				out = append(out, &r)
			}
			line = line[:0]
			continue
		}
		line = append(line, b)
	}
	if len(line) > 0 {
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("anchor: malformed trailing record: %w", err)
		}
		out = append(out, &r)
	}
	return out, nil
}

// HeadHash returns the contents of the head pointer file. Auditors compare
// this against an out-of-band copy (e.g. one they replicated to S3 or pinned
// in chat) to detect log rewrites at the anchor layer.
func (s *FileSink) HeadHash() (string, error) {
	buf, err := os.ReadFile(s.headPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	out := make([]byte, 0, len(buf))
	for _, b := range buf {
		if b == '\n' || b == '\r' || b == ' ' {
			continue
		}
		out = append(out, b)
	}
	return string(out), nil
}

// MultiSink fans out a single Publish call to several backends and reports
// per-sink results. A failure on one sink does not prevent the others from
// running, mirroring the threat model: more independent anchors = harder to
// roll back.
type MultiSink struct {
	Sinks []Sink
}

// Name implements Sink.
func (m *MultiSink) Name() string { return "multi" }

// Publish fans out. The first returned Record is from the first sink that
// succeeded; the joined error contains every sink failure.
func (m *MultiSink) Publish(c *checkpoint.Checkpoint) (*Record, error) {
	var first *Record
	var errs []error
	for _, s := range m.Sinks {
		rec, err := s.Publish(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
			continue
		}
		if first == nil {
			first = rec
		}
	}
	if first == nil {
		return nil, errors.Join(errs...)
	}
	if len(errs) > 0 {
		// Partial success is logged but not treated as fatal — the caller
		// will see the warning via the returned error if they want.
		return first, errors.Join(errs...)
	}
	return first, nil
}
