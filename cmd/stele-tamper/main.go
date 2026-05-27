// stele-tamper is an ATTACKER tool used solely for demonstration of stele's
// tamper-detection guarantees. It opens the BadgerDB directly (bypassing
// steled) and rewrites a stored entry's data. Running this then restarting
// steled should always cause steled to refuse to start.
//
// DO NOT ship this binary outside the demo.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/dgraph-io/badger/v4"
	"github.com/desledishant10/stele/pkg/logentry"
	"github.com/desledishant10/stele/pkg/obs"
)

// Set via `-ldflags "-X main.version=... -X main.commit=..."`.
var (
	version = "dev"
	commit  = "none"
)

func main() {
	obs.Init("tamper", nil)
	obs.SetBuildInfo(version, commit)
	dir := flag.String("dir", "", "data dir of the log to tamper with")
	idx := flag.Uint64("index", 0, "entry index to rewrite")
	newData := flag.String("data", "", "new payload (replaces .data field)")
	flag.Parse()
	if *dir == "" || *newData == "" {
		flag.Usage()
		os.Exit(2)
	}

	// Need to point at the actual badger sub-dir that steled uses.
	dbDir := *dir + "/db"
	if _, err := os.Stat(dbDir); err != nil {
		obs.Fatal("no badger dir", "path", dbDir)
	}

	opts := badger.DefaultOptions(dbDir)
	opts.Logger = nil
	db, err := badger.Open(opts)
	if err != nil {
		obs.Fatal("badger open failed", "err", err)
	}
	defer db.Close()

	key := make([]byte, len("entry/")+8)
	copy(key, "entry/")
	// big endian u64
	for i := 0; i < 8; i++ {
		key[len("entry/")+7-i] = byte((*idx) >> (i * 8))
	}

	err = db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		var raw []byte
		if err := item.Value(func(v []byte) error {
			raw = append([]byte(nil), v...)
			return nil
		}); err != nil {
			return err
		}
		var e logentry.Entry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		fmt.Printf("before: entry %d data = %q\n", e.Index, string(e.Envelope.Data))
		e.Envelope.Data = []byte(*newData)
		// IMPORTANT: We do *not* re-seal and we do not re-sign the envelope.
		// We leave EntryHash, LeafHash, and Envelope.Signature stale on
		// purpose — those are the three independent crypto bindings stele
		// uses to catch tampering.
		updated, err := json.Marshal(&e)
		if err != nil {
			return err
		}
		fmt.Printf("after : entry %d data = %q (NO hashes/signatures recomputed)\n", e.Index, string(e.Envelope.Data))
		return txn.Set(key, updated)
	})
	if err != nil {
		obs.Fatal("tamper failed", "err", err)
	}
	fmt.Println("tamper successful; BadgerDB now contains an entry whose stored data does not match its stored EntryHash.")
}
