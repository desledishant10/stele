package storage

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

// The replay-protection layer stores a small fingerprint of every
// accepted envelope so the same envelope cannot be ingested twice.
//
// Key shape: "replay/<envelope_hash_hex>" -> u64 entry index that
// accepted it. The value lets us point an auditor at the original
// entry when a replay attempt fires.
//
// Memory cost is bounded by the producer's retention policy. For
// stele's threat model — defending against an attacker who recorded a
// past valid request — a sliding window keyed on envelope hash is
// sufficient.

var prefixReplay = []byte("replay/")

func replayKey(envelopeHash []byte) []byte {
	hexHash := hex.EncodeToString(envelopeHash)
	k := make([]byte, len(prefixReplay)+len(hexHash))
	copy(k, prefixReplay)
	copy(k[len(prefixReplay):], hexHash)
	return k
}

// CheckAndRecordEnvelope returns nil if the envelope hash hasn't been
// seen before and atomically records it pointing at the given entry
// index. Returns an error containing the original entry index if a
// replay is detected.
func (s *Store) CheckAndRecordEnvelope(envelopeHash []byte, entryIdx uint64) error {
	return s.db.Update(func(txn *badger.Txn) error {
		k := replayKey(envelopeHash)
		if item, err := txn.Get(k); err == nil {
			var origIdx uint64
			_ = item.Value(func(val []byte) error {
				if len(val) == 8 {
					origIdx = binary.BigEndian.Uint64(val)
				}
				return nil
			})
			return fmt.Errorf("replay: envelope already accepted as entry %d", origIdx)
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], entryIdx)
		return txn.Set(k, v[:])
	})
}
