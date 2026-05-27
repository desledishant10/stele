package storage

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dgraph-io/badger/v4"
)

// Witness is the operator's record of an external witness it will ask to
// countersign checkpoints. QuantumPublicKey, when non-empty, switches
// the operator into "require hybrid cosig" mode for this witness:
// classical-only cosigs from this witness will not count toward the
// verifier's quorum.
type Witness struct {
	ID               string `json:"id"`
	URL              string `json:"url"`
	PublicKey        []byte `json:"public_key"`
	QuantumPublicKey []byte `json:"quantum_public_key,omitempty"`
	Description      string `json:"description,omitempty"`
	AddedAt          int64  `json:"added_at"`
}

var prefixWitness = []byte("witness/")

func witnessKey(id string) []byte {
	k := make([]byte, len(prefixWitness)+len(id))
	copy(k, prefixWitness)
	copy(k[len(prefixWitness):], id)
	return k
}

// RegisterWitness adds or updates a witness in the operator's local list.
func (s *Store) RegisterWitness(w *Witness) error {
	if w == nil || w.ID == "" {
		return errors.New("storage: witness id is required")
	}
	if w.URL == "" {
		return errors.New("storage: witness URL is required")
	}
	if len(w.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("storage: witness public key wrong length %d", len(w.PublicKey))
	}
	body, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(witnessKey(w.ID), body)
	})
}

// ListWitnesses iterates over registered witnesses.
func (s *Store) ListWitnesses(fn func(*Witness) error) error {
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefixWitness); it.ValidForPrefix(prefixWitness); it.Next() {
			err := it.Item().Value(func(val []byte) error {
				var w Witness
				if err := json.Unmarshal(val, &w); err != nil {
					return err
				}
				return fn(&w)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetWitness returns one witness by ID.
func (s *Store) GetWitness(id string) (*Witness, error) {
	var w *Witness
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(witnessKey(id))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return fmt.Errorf("storage: witness %q not registered", id)
		}
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			var rec Witness
			if err := json.Unmarshal(val, &rec); err != nil {
				return err
			}
			w = &rec
			return nil
		})
	})
	return w, err
}
