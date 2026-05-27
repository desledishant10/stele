// Package honeylog turns the audit log into a deception platform.
//
// Any entry can be flagged as a honeypot (canary). When a query — by
// index, by hash, by range, or via any read endpoint — touches a honey
// entry, an alert fires.
//
// Why: in a real breach, attackers read the audit log to learn what is
// known about them. They also read configuration logs to harvest fake
// credentials ("found AWS_ACCESS_KEY in /var/log/myapp.log"). Honey
// entries are bait planted in the log precisely to be read. Every lookup
// is high-confidence intrusion signal.
//
// The deception layer is independent of operator integrity: an attacker
// who fully controls the operator can SUPPRESS alerts, but cannot make
// the honey entry vanish from the log without breaking the Merkle root
// — at which point the witness/anchor layer fires its own alarm.
package honeylog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Alert describes a single honeypot trip.
type Alert struct {
	Origin    string `json:"origin"`     // log identifier
	EntryIdx  uint64 `json:"entry_idx"`  // honeyed entry
	LeafHash  []byte `json:"leaf_hash"`  // identifier the attacker saw
	CallerIP  string `json:"caller_ip"`  // best-effort client IP
	UserAgent string `json:"user_agent"`
	Path      string `json:"path"`       // HTTP path that fired
	Time      int64  `json:"time_ns"`    // server timestamp
	Note      string `json:"note,omitempty"`
}

// Sink consumes alerts. The implementation must be non-blocking from the
// caller's perspective; alerts that take long to deliver should be
// buffered or queued internally.
type Sink interface {
	Fire(ctx context.Context, a *Alert) error
}

// WebhookSink POSTs each alert as JSON to the configured URL.
type WebhookSink struct {
	URL    string
	HTTP   *http.Client
}

// NewWebhookSink returns a sink with a 5-second client timeout.
func NewWebhookSink(url string) *WebhookSink {
	return &WebhookSink{URL: url, HTTP: &http.Client{Timeout: 5 * time.Second}}
}

// Fire implements Sink.
func (s *WebhookSink) Fire(ctx context.Context, a *Alert) error {
	if s.URL == "" {
		return errors.New("honeylog: empty webhook URL")
	}
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("honeylog webhook: HTTP %d", resp.StatusCode)
	}
	return nil
}

// MultiSink fans out to every configured sink. A failure in one does not
// stop the others.
type MultiSink struct {
	Sinks []Sink
}

// Fire implements Sink.
func (m *MultiSink) Fire(ctx context.Context, a *Alert) error {
	var firstErr error
	for _, s := range m.Sinks {
		if err := s.Fire(ctx, a); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// StderrSink prints alerts to standard error. Useful for development.
type StderrSink struct{}

// Fire implements Sink.
func (s *StderrSink) Fire(_ context.Context, a *Alert) error {
	body, _ := json.MarshalIndent(a, "", "  ")
	fmt.Fprintf(stderr(), "[HONEYLOG ALERT] %s\n", body)
	return nil
}

// indirection for testing
var stderr = func() *fileWriter { return fwStderr }

type fileWriter struct{ w func(string) }

func (f *fileWriter) Write(b []byte) (int, error) { f.w(string(b)); return len(b), nil }

var fwStderr = &fileWriter{w: func(s string) { fmt.Print(s) }}
