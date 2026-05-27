package tripwire

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/desledishant10/stele/pkg/anchor"
	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/core"
	"github.com/desledishant10/stele/pkg/fwdsec"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/storage"
)

// buildRig sets up a tiny operator with N entries and returns the
// store + the latest checkpoint root + the db dir (for direct badger
// poking in tamper simulations).
func buildRig(t *testing.T, n int) (*storage.Store, *checkpoint.Checkpoint, string) {
	t.Helper()
	dir := t.TempDir()
	dbDir := filepath.Join(dir, "db")
	st, err := storage.Open(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fws, err := fwdsec.NewSigner("trip.local/log", filepath.Join(dir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	signer := checkpoint.NewSigner(fws)
	sink, err := anchor.NewFileSink(filepath.Join(dir, "anchor.log"))
	if err != nil {
		t.Fatal(err)
	}
	l, err := core.New(context.Background(), core.Options{
		Store:  st,
		Signer: signer,
		Sinks:  []anchor.Sink{sink},
	})
	if err != nil {
		t.Fatal(err)
	}

	prod, err := attest.NewSoftwareAttestor("trip-prod")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterProducer(&storage.Producer{
		ID:              "trip-prod",
		PublicKey:       prod.PublicKey(),
		AttestationType: string(attest.TypeSoftware),
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		env, err := prod.Sign("trip-src", []byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := l.Append(env, false); err != nil {
			t.Fatal(err)
		}
	}
	c, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	return st, c, dbDir
}

func TestRun_OK(t *testing.T) {
	st, c, _ := buildRig(t, 5)
	res, err := Run(context.Background(), st, c.Size, c.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tamper {
		t.Fatalf("tripwire flagged tamper on a clean log: %+v", res)
	}
}

func TestRun_DetectsLeafMutation(t *testing.T) {
	st, c, dbDir := buildRig(t, 5)
	// Close st so we can re-open Badger directly.
	st.Close()
	// Mutate the Envelope.Data field while keeping the JSON valid and
	// every hash field byte-identical (so iteration parses cleanly,
	// but the stored EntryHash no longer matches the canonical bytes
	// derived from the modified envelope — this is exactly the path
	// stele.Verify catches).
	mutateEntryDirect(t, dbDir, 2, func(raw []byte) []byte {
		var e logentry.Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		e.Envelope.Data = []byte("tampered payload")
		out, err := json.Marshal(&e)
		if err != nil {
			t.Fatal(err)
		}
		return out
	})
	st2, err := storage.Open(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	res, err := Run(context.Background(), st2, c.Size, c.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Tamper {
		t.Fatalf("tripwire did NOT flag mutated entry: %+v", res)
	}
	if res.FirstFailureIndex != 2 {
		t.Fatalf("expected first failure at index 2, got %d", res.FirstFailureIndex)
	}
}

func TestRun_DetectsLeafSwap(t *testing.T) {
	st, c, dbDir := buildRig(t, 5)
	st.Close()

	rawA := readEntryDirect(t, dbDir, 1)
	rawB := readEntryDirect(t, dbDir, 3)
	writeEntryDirect(t, dbDir, 1, rawB)
	writeEntryDirect(t, dbDir, 3, rawA)

	st2, err := storage.Open(dbDir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	res, err := Run(context.Background(), st2, c.Size, c.RootHash)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Tamper {
		t.Fatalf("tripwire did NOT flag swapped entries: %+v", res)
	}
}

func TestRun_EmptyLog(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.Open(filepath.Join(dir, "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// Empty tree root.
	res, err := Run(context.Background(), st, 0, emptyRoot())
	if err != nil {
		t.Fatal(err)
	}
	if res.Tamper {
		t.Fatalf("empty log flagged as tamper: %+v", res)
	}
}

// --- helpers that poke BadgerDB directly to simulate disk-level tamper ---
//
// These bypass storage.Store entirely — they're how an attacker with
// disk access (or a buggy ops script) would mutate stele's on-disk
// state. The Store must be closed before calling these because Badger
// holds an exclusive lock on the directory.

func mutateEntryDirect(t *testing.T, dbDir string, idx uint64, fn func([]byte) []byte) {
	t.Helper()
	raw := readEntryDirect(t, dbDir, idx)
	writeEntryDirect(t, dbDir, idx, fn(raw))
}

func openBadger(t *testing.T, dbDir string) *badger.DB {
	t.Helper()
	opts := badger.DefaultOptions(dbDir)
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func entryKey(idx uint64) []byte {
	key := make([]byte, len("entry/")+8)
	copy(key, "entry/")
	for i := 0; i < 8; i++ {
		key[len("entry/")+7-i] = byte(idx >> (i * 8))
	}
	return key
}

func readEntryDirect(t *testing.T, dbDir string, idx uint64) []byte {
	t.Helper()
	db := openBadger(t, dbDir)
	defer db.Close()
	var raw []byte
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(entryKey(idx))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			raw = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeEntryDirect(t *testing.T, dbDir string, idx uint64, raw []byte) {
	t.Helper()
	db := openBadger(t, dbDir)
	defer db.Close()
	err := db.Update(func(txn *badger.Txn) error {
		return txn.Set(entryKey(idx), raw)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// emptyRoot returns the RFC 6962 empty tree root for the size==0 case.
// Imported lazily so the test file doesn't drag in pkg/merkle just to
// re-derive a constant.
func emptyRoot() []byte {
	// SHA-256 of empty string per RFC 6962.
	// Matches merkle.Hasher.EmptyRoot().
	return []byte{
		0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
		0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
		0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
		0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
	}
}
