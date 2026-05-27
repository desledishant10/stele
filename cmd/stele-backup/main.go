// stele-backup is the operator-side disaster recovery tool. It streams
// a restorable backup of the BadgerDB log to a file (or stdout) using
// Badger's native incremental backup format.
//
// Use cases:
//
//   - Scheduled hot backup: cron / systemd timer that runs
//     `stele-backup snapshot --dir <log> --out s3://bucket/...` and
//     uploads to durable off-host storage.
//
//   - Pre-rotation snapshot: run before a manual key rotation so a
//     buggy rotation cert never costs the historical log.
//
//   - Restore drill: pair with `stele-backup restore` on a clean dir
//     to verify the backup is recoverable. RECOVERY.md mandates running
//     this drill at least quarterly.
//
// Quickstart:
//
//	stele-backup snapshot --dir ./data --out ./backup.bin
//	stele-backup restore  --dir ./restored --in  ./backup.bin
//
// IMPORTANT — concurrency:
//
//   BadgerDB holds an exclusive directory lock while the DB is open.
//   That means stele-backup snapshot CANNOT run while steled is also
//   running against the same data dir. Two production-safe patterns:
//
//     1. Brief pause: SIGTERM steled, run stele-backup snapshot, restart
//        steled. With --checkpoint-every and --anchor-every keeping the
//        external Rekor anchor fresh, a few seconds of unavailability
//        is acceptable for most logs.
//
//     2. Filesystem snapshot: ZFS / LVM / btrfs / EBS-snapshot the
//        data dir while steled is running (atomic, no downtime), mount
//        the snapshot read-only, point stele-backup at the SNAPSHOT
//        dir, not the live dir. Recommended for high-availability
//        deployments.
//
// IMPORTANT — scope:
//
//   This tool only backs up the entry/checkpoint/anchor database. The
//   rotation chain (chain.json + on-disk key files OR the HSM-resident
//   keys) is OUT of scope here — back that up separately with
//   stele-export-chain. The log database is useless without the chain,
//   and vice versa.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/desledishant10/stele/pkg/obs"
	"github.com/desledishant10/stele/pkg/storage"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("backup", nil)
	obs.SetBuildInfo(version, commit)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sub := os.Args[1]
	flag.CommandLine = flag.NewFlagSet(sub, flag.ExitOnError)
	switch sub {
	case "snapshot":
		if err := snapshot(os.Args[2:]); err != nil {
			obs.Fatal("snapshot failed", "err", err)
		}
	case "restore":
		if err := restore(os.Args[2:]); err != nil {
			obs.Fatal("restore failed", "err", err)
		}
	case "help", "-h", "--help":
		usage()
	default:
		obs.Error("unknown subcommand", "got", sub)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `stele-backup — durable backup tool for stele logs

Subcommands:
  snapshot --dir <log-data-dir> --out <file|->  [--since <version>]
  restore  --dir <empty-data-dir> --in <file|->

  snapshot writes a streaming backup of <log-data-dir>/db to the named
  output. Use "-" for stdout; pipe into your cloud-storage uploader.

  restore re-creates a BadgerDB at <empty-data-dir>/db from a
  previously-captured snapshot. The destination MUST be empty.

After restore, run "stele verify" against the restored data dir to
confirm chain integrity before pointing steled at it.`)
}

func snapshot(args []string) error {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	dir := fs.String("dir", "", "stele data directory (the parent of db/)")
	out := fs.String("out", "", `output path; "-" writes to stdout`)
	since := fs.Uint64("since", 0, "incremental: only back up keys with version > this")
	_ = fs.Parse(args)
	if *dir == "" || *out == "" {
		return errors.New("--dir and --out are required")
	}

	dbDir := *dir + "/db"
	if _, err := os.Stat(dbDir); err != nil {
		return fmt.Errorf("no badger dir at %s", dbDir)
	}
	st, err := storage.Open(dbDir)
	if err != nil {
		return err
	}
	defer st.Close()

	var w *os.File
	if *out == "-" {
		w = os.Stdout
	} else {
		w, err = os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open output: %w", err)
		}
		defer w.Close()
	}

	maxVer, err := st.Backup(w, *since)
	if err != nil {
		return fmt.Errorf("backup stream: %w", err)
	}
	if *out != "-" {
		if err := w.Sync(); err != nil {
			return fmt.Errorf("fsync: %w", err)
		}
	}
	obs.Info("snapshot complete",
		"dir", dbDir,
		"out", *out,
		"since", *since,
		"highest_version", maxVer)
	return nil
}

func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dir := fs.String("dir", "", "destination data directory (must be empty)")
	in := fs.String("in", "", `input path; "-" reads from stdin`)
	maxPending := fs.Int("max-pending", 256, "max in-flight writes during restore")
	_ = fs.Parse(args)
	if *dir == "" || *in == "" {
		return errors.New("--dir and --in are required")
	}

	dbDir := *dir + "/db"
	if entries, err := os.ReadDir(dbDir); err == nil && len(entries) > 0 {
		return fmt.Errorf("destination %s is not empty — refusing to restore over existing data", dbDir)
	}
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return err
	}

	st, err := storage.Open(dbDir)
	if err != nil {
		return err
	}
	defer st.Close()

	var r *os.File
	if *in == "-" {
		r = os.Stdin
	} else {
		r, err = os.Open(*in)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer r.Close()
	}

	if err := st.Restore(r, *maxPending); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	obs.Info("restore complete",
		"dir", dbDir,
		"in", *in,
		"next", "run 'stele verify' to confirm chain integrity before serving")
	return nil
}
