package auditpdf

import (
	"bytes"
	"testing"
	"time"

	"github.com/desledishant10/stele/pkg/audit"
)

// TestRender_PassReport: a clean PASS report renders to a valid PDF
// header + non-trivial content.
func TestRender_PassReport(t *testing.T) {
	report := &audit.Report{
		OperatorURL: "https://stele.example.com",
		Origin:      "example.com/audit",
		Size:        1234,
		AuditTime:   time.Now().UTC(),
		Status:      audit.StatusPass,
		TrustAnchor: audit.TrustAnchorSummary{
			Source:           "dnssec",
			RootPublicKeyHex: "0a0b0c0d0e0f10111213141516171819",
			RootKeyID:        "0a0b0c0d0e0f1011",
			MatchedOnServer:  true,
		},
		Chain: audit.ChainSummary{
			Origin:      "example.com/audit",
			ActiveEpoch: 3,
			Epochs:      4,
			Verified:    true,
			EpochSummary: []audit.EpochSummary{
				{Epoch: 0, KeyID: "aaaaaa", Hybrid: true},
				{Epoch: 1, KeyID: "bbbbbb", Hybrid: true},
				{Epoch: 2, KeyID: "cccccc", Hybrid: true},
				{Epoch: 3, KeyID: "dddddd", Hybrid: true, Threshold: true},
			},
		},
		LatestCheckpoint: audit.CheckpointSummary{
			Size:          1234,
			RootHashHex:   "ababababababababababababababababababababababababababababababab",
			Epoch:         3,
			Verified:      true,
			HybridSigned:  true,
			ThresholdMode: true,
			WitnessCount:  3,
			BeaconBound:   true,
			BeaconSource:  "drand",
			Witnesses: []audit.WitnessSig{
				{WitnessID: "witness-a", KeyID: "abc123"},
				{WitnessID: "witness-b", KeyID: "def456"},
				{WitnessID: "witness-c", KeyID: "789aaa"},
			},
		},
		Samples: []audit.InclusionSample{
			{Index: 0, Producer: "alice", Verified: true},
			{Index: 500, Producer: "bob", Verified: true},
			{Index: 1000, Producer: "alice", Verified: true},
		},
	}
	body, err := Render(report)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatalf("output is not a PDF (no %%PDF- header): %q", body[:min(20, len(body))])
	}
	if len(body) < 2000 {
		t.Fatalf("PDF too small (%d bytes); expected at least 2 KiB of content", len(body))
	}
}

// TestRender_FailReport: a failure report still produces a
// well-formed PDF. We can't reliably grep for visible strings in the
// raw output because content streams are deflate-compressed; instead
// we verify the PDF is structurally valid (header + trailer) and that
// it has enough content to fit the findings (each finding adds ~80
// bytes to the compressed stream — three of them gives us > 4 KiB
// vs the empty-report baseline of ~1.4 KiB).
func TestRender_FailReport(t *testing.T) {
	report := &audit.Report{
		OperatorURL: "https://stele.bad.example.com",
		Status:      audit.StatusFail,
		AuditTime:   time.Now().UTC(),
		TrustAnchor: audit.TrustAnchorSummary{
			RootPublicKeyHex: "deadbeef",
			RootKeyID:        "deadbeef",
		},
		Findings: []string{
			"trust anchor mismatch: server's claimed root does not match the caller-supplied root anchor",
			"checkpoint signature verification failed: invalid signature",
			"chain verification failed: epoch 2 sig invalid",
		},
	}
	body, err := Render(report)
	if err != nil {
		t.Fatal(err)
	}
	assertPDF(t, body)
	// Roughly: an empty report renders to ~1.4 KiB; each findings line
	// adds noticeable compressed content. 2 KiB+ confirms findings
	// rendered.
	if len(body) < 2000 {
		t.Fatalf("PDF too small to have rendered the findings section: %d bytes", len(body))
	}
}

// TestRender_EmptyReportSurvives: a near-empty report (no chain, no
// checkpoint, no samples) renders without errors. Useful when the
// audit aborts after the first failed call.
func TestRender_EmptyReportSurvives(t *testing.T) {
	report := &audit.Report{
		OperatorURL: "https://x",
		Status:      audit.StatusFail,
		Findings:    []string{"failed to fetch /pubkey: connection refused"},
	}
	body, err := Render(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 1000 {
		t.Fatalf("PDF too small")
	}
}

// assertPDF checks the bytes look like a valid PDF: starts with the
// magic %PDF- header and ends with %%EOF.
func assertPDF(t *testing.T, body []byte) {
	t.Helper()
	if !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatalf("output missing %%PDF- header: %q", body[:min(20, len(body))])
	}
	if !bytes.Contains(body[max(0, len(body)-1024):], []byte("%%EOF")) {
		t.Fatalf("output missing %s trailer", "%%EOF")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
