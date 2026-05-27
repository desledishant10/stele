package anchor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/desledishant10/stele/pkg/checkpoint"
)

// RekorSink anchors stele checkpoints into Sigstore Rekor — a globally
// public, append-only transparency log run by the Sigstore project.
//
// Once a checkpoint is accepted by Rekor, the operator cannot retract it
// without also breaking Rekor's own integrity (which would be detected
// by every Rekor monitor on the internet, including Sigstore's).
//
// The MVP submits a "hashedrekord" entry — Rekor's simplest type. The
// signature format we use here is bespoke (Ed25519 over checkpoint bytes
// with the operator's epoch public key in raw form), which Rekor's
// strict validators may reject. In that case, the sink falls back to
// local persistence with the payload that *would* have been submitted —
// useful for offline demos and for shipping the submission via a
// separate channel (e.g. ops-team batch import).
//
// To upgrade to a fully Rekor-compliant submission for production,
// switch SignatureFormat to "ssh" or "x509" and adjust Encode().
type RekorSink struct {
	Endpoint        string // e.g. https://rekor.sigstore.dev
	HTTP            *http.Client
	FallbackPath    string // file to append-only if Rekor refuses
	StrictRekor     bool   // if true, errors propagate; if false, fall back on 4xx
	SignatureFormat string // "raw" (Ed25519), "ssh" (OpenSSH), "x509" (PEM)
}

// NewRekorSink returns a sink targeting Sigstore's public Rekor instance.
// Use a self-hosted endpoint for environments that cannot egress.
func NewRekorSink(endpoint, fallbackPath string) *RekorSink {
	if endpoint == "" {
		endpoint = "https://rekor.sigstore.dev"
	}
	return &RekorSink{
		Endpoint:        endpoint,
		HTTP:            &http.Client{Timeout: 15 * time.Second},
		FallbackPath:    fallbackPath,
		StrictRekor:     false,
		SignatureFormat: "raw",
	}
}

// Name implements Sink.
func (s *RekorSink) Name() string { return "rekor:" + s.Endpoint }

// Publish submits the checkpoint to Rekor. The Record's SinkRef is the
// Rekor UUID on success, or the fallback file offset on graceful failure.
func (s *RekorSink) Publish(c *checkpoint.Checkpoint) (*Record, error) {
	if c == nil || c.Signature == nil {
		return nil, errors.New("rekor: refusing to publish unsigned checkpoint")
	}
	body, err := s.encode(c)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		if s.StrictRekor {
			return nil, err
		}
		return s.fallback(c, body, "network: "+err.Error())
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		if s.StrictRekor {
			return nil, fmt.Errorf("rekor: HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		return s.fallback(c, body, fmt.Sprintf("rekor HTTP %d: %s", resp.StatusCode, truncate(respBody, 200)))
	}
	// Parse Rekor's UUID out of the response (it's a map with one key).
	var parsed map[string]json.RawMessage
	_ = json.Unmarshal(respBody, &parsed)
	var uuid string
	for k := range parsed {
		uuid = k
		break
	}
	sum := sha256.Sum256(c.Canonical())
	return &Record{
		Checkpoint: c,
		SinkName:   s.Name(),
		SinkRef:    "rekor_uuid=" + uuid,
		AnchoredAt: time.Now().UnixNano(),
		RecordHash: hex.EncodeToString(sum[:]),
	}, nil
}

// encode builds the Rekor submission body. Format intentionally simple —
// see package doc for production caveats.
func (s *RekorSink) encode(c *checkpoint.Checkpoint) ([]byte, error) {
	canon := c.Canonical()
	sum := sha256.Sum256(canon)
	body := map[string]any{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]any{
			"data": map[string]any{
				"hash": map[string]any{
					"algorithm": "sha256",
					"value":     hex.EncodeToString(sum[:]),
				},
			},
			"signature": map[string]any{
				"format":  s.SignatureFormat,
				"content": base64Encode(c.Signature),
				"publicKey": map[string]any{
					"content": base64Encode(stele_meta(c)),
				},
			},
		},
	}
	return json.Marshal(body)
}

func (s *RekorSink) fallback(c *checkpoint.Checkpoint, body []byte, reason string) (*Record, error) {
	sum := sha256.Sum256(c.Canonical())
	rec := &Record{
		Checkpoint: c,
		SinkName:   s.Name(),
		SinkRef:    "fallback: " + reason,
		AnchoredAt: time.Now().UnixNano(),
		RecordHash: hex.EncodeToString(sum[:]),
	}
	if s.FallbackPath != "" {
		line, _ := json.Marshal(map[string]any{
			"reason":  reason,
			"payload": json.RawMessage(body),
			"record":  rec,
			"at":      rec.AnchoredAt,
		})
		_ = appendLine(s.FallbackPath, line)
	}
	return rec, nil
}

// stele_meta returns metadata identifying the signing public key the
// caller-supplied checkpoint claims. Auditors use this to look up the
// matching cert in the operator's rotation chain.
func stele_meta(c *checkpoint.Checkpoint) []byte {
	body, _ := json.Marshal(map[string]any{
		"origin":    c.Origin,
		"epoch_idx": c.EpochIdx,
		"key_id":    c.KeyID,
	})
	return body
}
