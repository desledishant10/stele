// Package auditpdf renders an audit.Report as a self-contained PDF.
// The output is intended as the customer-facing deliverable: a
// non-technical compliance reviewer can read the verdict on page 1
// and the cryptographic evidence on subsequent pages.
//
// The PDF is pure-Go (go-pdf/fpdf, no C deps), so it cross-compiles
// to every platform stele supports.
package auditpdf

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/desledishant10/stele/pkg/audit"
	"github.com/go-pdf/fpdf"
)

// Render returns the PDF bytes for the given audit Report.
func Render(r *audit.Report) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 25)
	pdf.SetFont("Helvetica", "", 10)

	// Page footer with page number + report identifier.
	footer := func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 10,
			fmt.Sprintf("Stele audit — %s — page %d/{nb}",
				r.AuditTime.Format(time.RFC3339), pdf.PageNo()),
			"", 0, "C", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	}
	pdf.SetFooterFunc(footer)
	pdf.AliasNbPages("")

	renderCover(pdf, r)
	renderVerdict(pdf, r)
	renderTrustAnchor(pdf, r)
	renderChain(pdf, r)
	renderCheckpoint(pdf, r)
	if len(r.Samples) > 0 {
		renderSamples(pdf, r)
	}
	renderFindings(pdf, r)

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("auditpdf: render: %w", err)
	}
	return buf.Bytes(), nil
}

// --- sections ---

func renderCover(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 22)
	pdf.CellFormat(0, 12, "Stele Audit Report", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 12)
	pdf.Ln(2)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 6, "Provenance-anchored audit log", "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(8)

	kv := [][2]string{
		{"Log origin", r.Origin},
		{"Operator URL", r.OperatorURL},
		{"Audit timestamp", r.AuditTime.Format(time.RFC3339)},
		{"Log size at audit", fmt.Sprintf("%d entries", r.Size)},
		{"Trust anchor source", nonEmpty(r.TrustAnchor.Source, "(unspecified — NOT compliance-grade)")},
	}
	for _, p := range kv {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(50, 6, p[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(0, 6, p[1], "", "L", false)
	}
}

func renderVerdict(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.Ln(4)
	pdf.SetDrawColor(220, 220, 220)
	pdf.SetLineWidth(0.3)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(0, 8, "Verdict", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "B", 18)
	switch r.Status {
	case audit.StatusPass:
		pdf.SetTextColor(0, 130, 0)
	case audit.StatusWarn:
		pdf.SetTextColor(200, 130, 0)
	case audit.StatusFail:
		pdf.SetTextColor(180, 0, 0)
	}
	pdf.CellFormat(0, 12, string(r.Status), "", 1, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)

	pdf.SetFont("Helvetica", "", 10)
	pdf.Ln(2)
	pdf.MultiCell(0, 5,
		verdictNarrative(r), "", "L", false)
}

func verdictNarrative(r *audit.Report) string {
	switch r.Status {
	case audit.StatusPass:
		return "All cryptographic checks succeeded. Every layer this audit examined " +
			"(trust anchor, rotation chain, latest checkpoint, witness cosignatures, " +
			"inclusion sample) is internally consistent and matches the operator's claims."
	case audit.StatusWarn:
		return "Cryptographic checks pass, but at least one finding requires operator " +
			"attention before this run is treated as compliance evidence. See \"Findings\" below."
	case audit.StatusFail:
		return "One or more cryptographic checks FAILED. This log cannot be considered " +
			"intact based on this run. See \"Findings\" for the specific defect."
	}
	return ""
}

func renderTrustAnchor(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "1. Trust anchor", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.Ln(1)

	kv := [][2]string{
		{"Root public key ID", r.TrustAnchor.RootKeyID},
		{"Root public key (hex)", wrap(r.TrustAnchor.RootPublicKeyHex, 70)},
		{"Source of trust anchor", nonEmpty(r.TrustAnchor.Source, "(unverified)")},
		{"Matches operator-reported root", yesNo(r.TrustAnchor.MatchedOnServer)},
	}
	if r.TrustAnchor.Notes != "" {
		kv = append(kv, [2]string{"Notes", r.TrustAnchor.Notes})
	}
	renderKV(pdf, kv)
}

func renderChain(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "2. Forward-secure rotation chain", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.Ln(1)

	kv := [][2]string{
		{"Origin", r.Chain.Origin},
		{"Active epoch", fmt.Sprintf("%d", r.Chain.ActiveEpoch)},
		{"Total epochs in chain", fmt.Sprintf("%d", r.Chain.Epochs)},
		{"Chain verifies against trust anchor", yesNo(r.Chain.Verified)},
	}
	if r.Chain.VerifyError != "" {
		kv = append(kv, [2]string{"Verification error", r.Chain.VerifyError})
	}
	renderKV(pdf, kv)

	if len(r.Chain.EpochSummary) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 6, "Per-epoch summary:", "", 1, "L", false, 0, "")
		pdf.SetFont("Courier", "", 9)
		pdf.CellFormat(20, 5, "Epoch", "B", 0, "L", false, 0, "")
		pdf.CellFormat(35, 5, "Key ID", "B", 0, "L", false, 0, "")
		pdf.CellFormat(55, 5, "Started", "B", 0, "L", false, 0, "")
		pdf.CellFormat(25, 5, "Hybrid?", "B", 0, "L", false, 0, "")
		pdf.CellFormat(25, 5, "Threshold?", "B", 1, "L", false, 0, "")
		for _, e := range r.Chain.EpochSummary {
			pdf.CellFormat(20, 5, fmt.Sprintf("%d", e.Epoch), "", 0, "L", false, 0, "")
			pdf.CellFormat(35, 5, e.KeyID, "", 0, "L", false, 0, "")
			pdf.CellFormat(55, 5, time.Unix(0, e.StartedAt).UTC().Format(time.RFC3339), "", 0, "L", false, 0, "")
			pdf.CellFormat(25, 5, yesNo(e.Hybrid), "", 0, "L", false, 0, "")
			pdf.CellFormat(25, 5, yesNo(e.Threshold), "", 1, "L", false, 0, "")
		}
	}
}

func renderCheckpoint(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "3. Latest signed checkpoint", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.Ln(1)

	c := r.LatestCheckpoint
	kv := [][2]string{
		{"Tree size", fmt.Sprintf("%d entries", c.Size)},
		{"Merkle root (hex)", wrap(c.RootHashHex, 70)},
		{"Signed at", c.SignedAt.UTC().Format(time.RFC3339)},
		{"Signed by epoch", fmt.Sprintf("%d", c.Epoch)},
		{"Signature verifies", yesNo(c.Verified)},
		{"Hybrid PQ signed (Dilithium3)", yesNo(c.HybridSigned)},
		{"Threshold-signed (t-of-N)", yesNo(c.ThresholdMode)},
		{"Witness cosignatures", fmt.Sprintf("%d", c.WitnessCount)},
		{"Beacon-bound (drand)", yesNo(c.BeaconBound)},
	}
	if c.BeaconSource != "" {
		kv = append(kv, [2]string{"Beacon source", c.BeaconSource})
	}
	if c.VerifyError != "" {
		kv = append(kv, [2]string{"Verification error", c.VerifyError})
	}
	renderKV(pdf, kv)

	if len(c.Witnesses) > 0 {
		pdf.Ln(2)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(0, 6, "Witness cosignatures:", "", 1, "L", false, 0, "")
		pdf.SetFont("Courier", "", 9)
		pdf.CellFormat(80, 5, "Witness ID", "B", 0, "L", false, 0, "")
		pdf.CellFormat(40, 5, "Key ID", "B", 1, "L", false, 0, "")
		for _, w := range c.Witnesses {
			pdf.CellFormat(80, 5, w.WitnessID, "", 0, "L", false, 0, "")
			pdf.CellFormat(40, 5, w.KeyID, "", 1, "L", false, 0, "")
		}
	}
}

func renderSamples(pdf *fpdf.Fpdf, r *audit.Report) {
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "4. Inclusion-proof sample", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	pdf.MultiCell(0, 5,
		"Entries were sampled uniformly across the log and their Merkle "+
			"inclusion proofs verified against the checkpoint's root.", "", "L", false)
	pdf.Ln(1)

	pdf.SetFont("Courier", "", 9)
	pdf.CellFormat(20, 5, "Index", "B", 0, "L", false, 0, "")
	pdf.CellFormat(50, 5, "Producer", "B", 0, "L", false, 0, "")
	pdf.CellFormat(25, 5, "Verified?", "B", 0, "L", false, 0, "")
	pdf.CellFormat(70, 5, "Error (if any)", "B", 1, "L", false, 0, "")
	pass, fail := 0, 0
	for _, s := range r.Samples {
		pdf.CellFormat(20, 5, fmt.Sprintf("%d", s.Index), "", 0, "L", false, 0, "")
		pdf.CellFormat(50, 5, truncate(s.Producer, 24), "", 0, "L", false, 0, "")
		if s.Verified {
			pdf.SetTextColor(0, 130, 0)
			pdf.CellFormat(25, 5, "PASS", "", 0, "L", false, 0, "")
			pass++
		} else {
			pdf.SetTextColor(180, 0, 0)
			pdf.CellFormat(25, 5, "FAIL", "", 0, "L", false, 0, "")
			fail++
		}
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(70, 5, truncate(s.Error, 35), "", 1, "L", false, 0, "")
	}
	pdf.Ln(2)
	pdf.SetFont("Helvetica", "I", 9)
	pdf.CellFormat(0, 5, fmt.Sprintf("  %d of %d samples verified.", pass, pass+fail), "", 1, "L", false, 0, "")
}

func renderFindings(pdf *fpdf.Fpdf, r *audit.Report) {
	if len(r.Findings) == 0 {
		return
	}
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.CellFormat(0, 7, "Findings", "", 1, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 10)
	for i, f := range r.Findings {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(8, 5, fmt.Sprintf("%d.", i+1), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(0, 5, f, "", "L", false)
	}
}

// --- small helpers ---

func renderKV(pdf *fpdf.Fpdf, kv [][2]string) {
	for _, p := range kv {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(60, 5, p[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.MultiCell(0, 5, p[1], "", "L", false)
	}
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func wrap(s string, width int) string {
	if len(s) <= width {
		return s
	}
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteByte('\n')
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
