// stele-export-chain prints the operator's rotation chain in formats
// suitable for off-host disaster recovery.
//
// The rotation chain is the trust anchor for the entire log: if you
// lose it, no auditor can verify that any historical entry came from
// you, and your fresh boot of steled creates a *different* chain that
// shares no continuity with the lost one. Losing the chain is
// unrecoverable.
//
// What you should do, in priority order:
//
//  1. At log inception:
//       stele-export-chain identity --dir ./data --format paper
//     Print the resulting PEM block + QR. Put a physical copy in a
//     locked safe. This single page is the *minimum* needed for an
//     auditor to verify your log if everything else is destroyed.
//
//  2. After every key rotation:
//       stele-export-chain full --dir ./data --out backup-N.json
//     Ship to off-host durable storage (S3 + object lock, vault, etc.).
//     Without this, you cannot serve auditors who already know an older
//     root pubkey but need to follow the rotation chain forward.
//
//  3. Quarterly:
//       Run a recovery drill (RECOVERY.md §3) using the most recent
//       full export. Record the time-to-recovery.
//
// This tool ONLY reads — it never modifies the chain.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/obs"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("export-chain", nil)
	obs.SetBuildInfo(version, commit)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "identity":
		if err := identity(os.Args[2:]); err != nil {
			obs.Fatal("identity export failed", "err", err)
		}
	case "full":
		if err := full(os.Args[2:]); err != nil {
			obs.Fatal("full export failed", "err", err)
		}
	case "help", "-h", "--help":
		usage()
	default:
		obs.Error("unknown subcommand", "got", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `stele-export-chain — off-host backup of the operator trust anchor

Subcommands:
  identity --dir <data> [--format paper|json]
      Emit ONLY the root pubkey + chain digest in a form suitable for
      physical safekeeping. Default --format paper prints a labelled
      PEM-like block; --format json emits structured fields for
      automation.

  full --dir <data> --out <file|->
      Emit the entire rotation chain (every epoch's RotationCert) as
      canonical JSON. Required to verify entries signed by post-root
      epochs. Run after every rotation.

Common flag:
  --dir <data>   the steled data directory (parent of keys/chain.json)`)
}

// identity emits the root pubkey + chain digest only. Designed for
// human safekeeping; the output should be small enough to print on
// one page.
func identity(args []string) error {
	fs := flag.NewFlagSet("identity", flag.ExitOnError)
	dir := fs.String("dir", "", "steled data directory")
	format := fs.String("format", "paper", "output: paper | json")
	_ = fs.Parse(args)
	if *dir == "" {
		return errors.New("--dir is required")
	}
	chain, err := readChain(*dir)
	if err != nil {
		return err
	}
	if len(chain.Certs) == 0 {
		return errors.New("chain has no certs (corrupt or uninitialised)")
	}
	root := chain.Certs[0]
	digest := sha256.Sum256(mustMarshal(chain))

	switch *format {
	case "paper":
		fmt.Println("==== STELE LOG ROOT IDENTITY — SEAL AND STORE PHYSICALLY ====")
		fmt.Printf("origin       : %s\n", chain.Origin)
		fmt.Printf("created_at   : %s\n", time.Unix(0, root.StartedAt).UTC().Format(time.RFC3339))
		fmt.Printf("root_keyid   : %s\n", fwdsec.KeyID(root.PublicKey))
		fmt.Println("root_pubkey  : (base64 Ed25519, 32 bytes)")
		fmt.Println(wrap(base64.StdEncoding.EncodeToString(root.PublicKey), 64))
		if len(root.QuantumPublicKey) > 0 {
			fmt.Println("root_qpubkey : (base64 Dilithium3, 1952 bytes)")
			fmt.Println(wrap(base64.StdEncoding.EncodeToString(root.QuantumPublicKey), 64))
		}
		fmt.Printf("chain_digest : %s\n", hex.EncodeToString(digest[:]))
		fmt.Printf("epoch        : %d (most recent in this export)\n", chain.Certs[len(chain.Certs)-1].Epoch)
		fmt.Println()
		fmt.Println("VERIFICATION: an auditor can later confirm any signed checkpoint")
		fmt.Println("against this root_pubkey using:")
		fmt.Printf("    stele audit --server <url> --root <base64 above>\n")
		fmt.Println()
		fmt.Println("This page IS the trust anchor. Treat it like a master")
		fmt.Println("password — lose it and the entire log becomes unverifiable.")
		fmt.Println("==============================================================")
	case "json":
		out := map[string]any{
			"origin":      chain.Origin,
			"created_at":  time.Unix(0, root.StartedAt).UTC().Format(time.RFC3339),
			"root_keyid":  fwdsec.KeyID(root.PublicKey),
			"root_pubkey": base64.StdEncoding.EncodeToString(root.PublicKey),
			"chain_digest": hex.EncodeToString(digest[:]),
			"epoch":       chain.Certs[len(chain.Certs)-1].Epoch,
		}
		if len(root.QuantumPublicKey) > 0 {
			out["root_qpubkey"] = base64.StdEncoding.EncodeToString(root.QuantumPublicKey)
		}
		body, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(body))
	default:
		return fmt.Errorf("unknown --format %q (expected paper|json)", *format)
	}
	return nil
}

// full emits every cert in the chain so an auditor can verify any
// post-root epoch. Output is canonical JSON.
func full(args []string) error {
	fs := flag.NewFlagSet("full", flag.ExitOnError)
	dir := fs.String("dir", "", "steled data directory")
	out := fs.String("out", "", `output path; "-" writes to stdout`)
	_ = fs.Parse(args)
	if *dir == "" || *out == "" {
		return errors.New("--dir and --out are required")
	}
	chain, err := readChain(*dir)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain: %w", err)
	}
	if *out == "-" {
		fmt.Println(string(body))
		return nil
	}
	if err := os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	digest := sha256.Sum256(body)
	obs.Info("full chain exported",
		"dir", *dir,
		"out", *out,
		"epochs", len(chain.Certs),
		"chain_digest", hex.EncodeToString(digest[:]))
	return nil
}

// readChain loads chain.json from <dir>/keys/chain.json without
// touching the active key file. Returns an error if the chain is
// missing — there is nothing to back up before init.
func readChain(dir string) (*fwdsec.Chain, error) {
	chainPath := filepath.Join(dir, "keys", "chain.json")
	buf, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", chainPath, err)
	}
	var c fwdsec.Chain
	if err := json.Unmarshal(buf, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", chainPath, err)
	}
	return &c, nil
}

func mustMarshal(v any) []byte {
	body, _ := json.Marshal(v)
	return body
}

// wrap breaks `s` into lines of at most `width` characters for paper
// printing. Use for base64 blobs; produces output a human can OCR or
// retype if needed.
func wrap(s string, width int) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteByte('\n')
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}
