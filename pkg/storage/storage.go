// Package storage is the persistence layer for the provenance log.
//
// Layout in BadgerDB (all big-endian integers):
//
//	entry/<u64 index>     -> JSON-encoded logentry.Entry
//	ckpt/<u64 size>       -> JSON-encoded checkpoint
//	anchor/<u64 size>     -> JSON-encoded anchor proof
//	meta/size             -> u64 (current tree size)
//	meta/head_hash        -> 32 bytes (EntryHash of last entry)
//
// The storage layer intentionally exposes no update or delete API for
// entries — appends are the only mutation. The underlying DB can still be
// tampered with by an attacker with disk access; that is exactly why we
// anchor checkpoints to an external transparency log.
package storage

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/dgraph-io/badger/v4"
	"github.com/desledishant10/stele/pkg/logentry"
)

var (
	prefixEntry  = []byte("entry/")
	prefixCkpt   = []byte("ckpt/")
	prefixAnchor = []byte("anchor/")
	keyMetaSize  = []byte("meta/size")
	keyMetaHead  = []byte("meta/head_hash")
)

// Store wraps a BadgerDB instance.
type Store struct {
	db *badger.DB
}

// Open creates or opens a Store at the given directory.
func Open(dir string) (*Store, error) {
	opts := badger.DefaultOptions(dir)
	opts.Logger = nil // quiet startup logs
	opts.SyncWrites = true
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", dir, err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Backup writes a streaming, restorable copy of every key with version
// strictly greater than `since` to w. Returns the highest version
// number observed — pass it as `since` on the next call to do an
// incremental backup.
//
// The backup format is Badger's native streaming format; restore with
// Restore on a *new, empty* Store directory. The output is opaque — do
// not assume any structure beyond "the bytes restore the DB."
func (s *Store) Backup(w io.Writer, since uint64) (uint64, error) {
	return s.db.Backup(w, since)
}

// Restore loads a previously-streamed Backup into this Store. The
// Store must be empty (newly opened on a fresh directory) — restoring
// into a populated DB is undefined.
//
// `maxPendingWrites` bounds memory during restore; 256 is a reasonable
// default for production hardware.
func (s *Store) Restore(r io.Reader, maxPendingWrites int) error {
	if maxPendingWrites <= 0 {
		maxPendingWrites = 256
	}
	return s.db.Load(r, maxPendingWrites)
}

// Size returns the number of entries currently stored.
func (s *Store) Size() (uint64, error) {
	var size uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyMetaSize)
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil // empty log
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) != 8 {
				return fmt.Errorf("meta/size has wrong length %d", len(val))
			}
			size = binary.BigEndian.Uint64(val)
			return nil
		})
	})
	return size, err
}

// HeadHash returns the EntryHash of the last entry, or 32 zero bytes if the
// log is empty.
func (s *Store) HeadHash() ([]byte, error) {
	head := make([]byte, 32)
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyMetaHead)
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			if len(val) != 32 {
				return fmt.Errorf("meta/head_hash has wrong length %d", len(val))
			}
			copy(head, val)
			return nil
		})
	})
	return head, err
}

// AppendEntry persists an entry. It is the caller's responsibility to have
// computed Index, PrevHash, and called Seal() — this method enforces those
// invariants and aborts on mismatch rather than silently fixing them.
func (s *Store) AppendEntry(e *logentry.Entry) error {
	if e.EntryHash == nil || e.LeafHash == nil {
		return errors.New("storage: entry not sealed")
	}
	return s.db.Update(func(txn *badger.Txn) error {
		curSize, err := readSize(txn)
		if err != nil {
			return err
		}
		if e.Index != curSize {
			return fmt.Errorf("storage: append out of order: have size %d, entry index %d",
				curSize, e.Index)
		}
		curHead, err := readHead(txn)
		if err != nil {
			return err
		}
		if !equalBytes(e.PrevHash, curHead) {
			return fmt.Errorf("storage: PrevHash %x does not match head %x",
				e.PrevHash, curHead)
		}
		// Reject if a key with this index somehow already exists.
		key := entryKey(e.Index)
		if _, err := txn.Get(key); err == nil {
			return fmt.Errorf("storage: entry %d already present", e.Index)
		} else if !errors.Is(err, badger.ErrKeyNotFound) {
			return err
		}
		buf, err := e.Marshal()
		if err != nil {
			return err
		}
		if err := txn.Set(key, buf); err != nil {
			return err
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], curSize+1)
		if err := txn.Set(keyMetaSize, size[:]); err != nil {
			return err
		}
		return txn.Set(keyMetaHead, append([]byte(nil), e.EntryHash...))
	})
}

// GetEntry fetches the entry at a given index.
func (s *Store) GetEntry(idx uint64) (*logentry.Entry, error) {
	var entry *logentry.Entry
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(entryKey(idx))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("storage: entry %d not found", idx)
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			e, err := logentry.Unmarshal(val)
			if err != nil {
				return err
			}
			entry = e
			return nil
		})
	})
	return entry, err
}

// IterateEntries calls fn for every entry in index order, starting from `from`
// (inclusive). Iteration stops if fn returns a non-nil error or if `ctx` is
// cancelled.
func (s *Store) IterateEntries(ctx context.Context, from uint64, fn func(*logentry.Entry) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()
		seek := entryKey(from)
		for it.Seek(seek); it.ValidForPrefix(prefixEntry); it.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			item := it.Item()
			err := item.Value(func(val []byte) error {
				e, err := logentry.Unmarshal(val)
				if err != nil {
					return err
				}
				return fn(e)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// SaveCheckpoint persists a checkpoint keyed by its tree size.
func (s *Store) SaveCheckpoint(treeSize uint64, body []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(checkpointKey(treeSize), body)
	})
}

// GetCheckpoint returns the most recent checkpoint at or before `atSize`, or
// nil if none.
func (s *Store) GetCheckpoint(atSize uint64) ([]byte, uint64, error) {
	var (
		body []byte
		size uint64
	)
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		it := txn.NewIterator(opts)
		defer it.Close()
		seek := checkpointKey(atSize)
		for it.Seek(seek); it.ValidForPrefix(prefixCkpt); it.Next() {
			item := it.Item()
			k := item.Key()
			if len(k) != len(prefixCkpt)+8 {
				continue
			}
			size = binary.BigEndian.Uint64(k[len(prefixCkpt):])
			if size > atSize {
				continue
			}
			return item.Value(func(val []byte) error {
				body = append([]byte(nil), val...)
				return nil
			})
		}
		return nil
	})
	return body, size, err
}

// LatestCheckpoint returns the highest-size checkpoint stored, or nil.
func (s *Store) LatestCheckpoint() ([]byte, uint64, error) {
	curSize, err := s.Size()
	if err != nil {
		return nil, 0, err
	}
	if curSize == 0 {
		return nil, 0, nil
	}
	return s.GetCheckpoint(curSize)
}

// SaveAnchor stores anchor metadata associated with a checkpoint of given size.
func (s *Store) SaveAnchor(treeSize uint64, body []byte) error {
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(anchorKey(treeSize), body)
	})
}

// IterateAnchors visits every saved anchor in ascending size order.
func (s *Store) IterateAnchors(fn func(size uint64, body []byte) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefixAnchor); it.ValidForPrefix(prefixAnchor); it.Next() {
			item := it.Item()
			k := item.Key()
			if len(k) != len(prefixAnchor)+8 {
				continue
			}
			size := binary.BigEndian.Uint64(k[len(prefixAnchor):])
			err := item.Value(func(val []byte) error {
				return fn(size, val)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// ---- internal helpers ----

func entryKey(idx uint64) []byte {
	k := make([]byte, len(prefixEntry)+8)
	copy(k, prefixEntry)
	binary.BigEndian.PutUint64(k[len(prefixEntry):], idx)
	return k
}

func checkpointKey(size uint64) []byte {
	k := make([]byte, len(prefixCkpt)+8)
	copy(k, prefixCkpt)
	binary.BigEndian.PutUint64(k[len(prefixCkpt):], size)
	return k
}

func anchorKey(size uint64) []byte {
	k := make([]byte, len(prefixAnchor)+8)
	copy(k, prefixAnchor)
	binary.BigEndian.PutUint64(k[len(prefixAnchor):], size)
	return k
}

func readSize(txn *badger.Txn) (uint64, error) {
	item, err := txn.Get(keyMetaSize)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var size uint64
	err = item.Value(func(val []byte) error {
		if len(val) != 8 {
			return fmt.Errorf("meta/size wrong length %d", len(val))
		}
		size = binary.BigEndian.Uint64(val)
		return nil
	})
	return size, err
}

func readHead(txn *badger.Txn) ([]byte, error) {
	item, err := txn.Get(keyMetaHead)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return make([]byte, 32), nil
	}
	if err != nil {
		return nil, err
	}
	var head []byte
	err = item.Value(func(val []byte) error {
		if len(val) != 32 {
			return fmt.Errorf("meta/head_hash wrong length %d", len(val))
		}
		head = append([]byte(nil), val...)
		return nil
	})
	return head, err
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Unused import guard for json.Marshal/Unmarshal (used in higher levels).
var _ = json.Marshal
