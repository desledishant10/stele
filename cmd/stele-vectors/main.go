// stele-vectors emits the deterministic known-answer test vectors
// auditors and SDK implementers use to confirm byte-level
// compatibility with the reference Go implementation.
//
// Output: a directory of small JSON files, one per vector family.
// Each file lists inputs + expected outputs; an SDK passes if it
// produces the same outputs given those inputs.
//
//	stele-vectors --out testdata/vectors
//
// Run from CI on every change to a wire-format file so any drift
// surfaces immediately. The result of running this tool is
// committed to git — that's the contract.
//
// Vector families produced:
//
//	envelope_canonical.json   Envelope.Canonical() outputs for assorted shapes
//	envelope_hash.json        Envelope.Hash() (= SHA-256 of canonical) outputs
//	envelope_signing.json     Full producer-signed envelopes with seeded ed25519 keys
//	merkle_root.json          Tree roots for assorted leaf sequences
//	merkle_inclusion.json     Inclusion proofs at specific (idx, size) pairs
//	merkle_consistency.json   Consistency proofs across (oldSize, newSize) pairs
//	checkpoint_canonical.json Checkpoint.Canonical() bytes (the operator-signed payload)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/desledishant10/stele/pkg/attest"
	"github.com/desledishant10/stele/pkg/checkpoint"
	"github.com/desledishant10/stele/pkg/merkle"
)

func main() {
	out := flag.String("out", "testdata/vectors", "directory to write vector files into")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "stele-vectors:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := emitEnvelopeCanonical(filepath.Join(dir, "envelope_canonical.json")); err != nil {
		return err
	}
	if err := emitEnvelopeHash(filepath.Join(dir, "envelope_hash.json")); err != nil {
		return err
	}
	if err := emitEnvelopeSigning(filepath.Join(dir, "envelope_signing.json")); err != nil {
		return err
	}
	if err := emitMerkleRoot(filepath.Join(dir, "merkle_root.json")); err != nil {
		return err
	}
	if err := emitMerkleInclusion(filepath.Join(dir, "merkle_inclusion.json")); err != nil {
		return err
	}
	if err := emitMerkleConsistency(filepath.Join(dir, "merkle_consistency.json")); err != nil {
		return err
	}
	if err := emitCheckpointCanonical(filepath.Join(dir, "checkpoint_canonical.json")); err != nil {
		return err
	}
	if err := emitIndexJSON(dir); err != nil {
		return err
	}
	fmt.Printf("wrote vector files to %s\n", dir)
	return nil
}

// --- envelope vectors ---

type envelopeCase struct {
	Name               string `json:"name"`
	ProducerID         string `json:"producer_id"`
	TimeNanos          int64  `json:"time_nanos"`
	Source             string `json:"source"`
	DataHex            string `json:"data_hex"`
	PublicKeyHex       string `json:"public_key_hex"`
	AttestationType    string `json:"attestation_type"`
	EvidenceHashHex    string `json:"evidence_hash_hex,omitempty"`
	QuantumPublicKey   string `json:"quantum_public_key_hex,omitempty"`
	ExpectedCanonHex   string `json:"expected_canonical_hex"`
	ExpectedHashHex    string `json:"expected_hash_hex"`
}

func envelopeCases() []envelopeCase {
	// Deterministic ed25519 pubkey: 32 bytes of 0x01.
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0x01
	}
	cases := []struct {
		Name      string
		Pid, Src  string
		Data      []byte
		Time      int64
		Type      string
		EvHash    []byte
		QPub      []byte
	}{
		{
			Name: "minimal_classical",
			Pid:  "alice",
			Time: 1700000000123456789,
			Src:  "/var/log/x",
			Data: []byte("hello"),
			Type: "software",
		},
		{
			Name: "empty_data_and_source",
			Pid:  "x",
			Time: 0,
			Src:  "",
			Data: []byte{},
			Type: "software",
		},
		{
			Name: "unicode_strings",
			Pid:  "ñame-é",
			Time: 1,
			Src:  "lögs",
			Data: []byte("data"),
			Type: "software",
		},
		{
			Name:   "with_evidence_hash",
			Pid:    "tpm-bound-prod",
			Time:   1700000000000000000,
			Src:    "/var/log/y",
			Data:   []byte("attested"),
			Type:   "tpm2",
			EvHash: sha256Sum([]byte("opaque attestation evidence")),
		},
		{
			Name: "large_data_1mib",
			Pid:  "alice",
			Time: 1700000000000000000,
			Src:  "/var/log/big",
			Data: bytes(0xAA, 1024*1024),
			Type: "software",
		},
		{
			Name: "hybrid_quantum_pubkey",
			Pid:  "alice",
			Time: 1700000000000000000,
			Src:  "/var/log/x",
			Data: []byte("hello"),
			Type: "software",
			QPub: bytes(0xBB, 1952),
		},
	}
	out := make([]envelopeCase, 0, len(cases))
	for _, c := range cases {
		env := &attest.Envelope{
			ProducerID:       c.Pid,
			TimeNanos:        c.Time,
			Source:           c.Src,
			Data:             c.Data,
			PublicKey:        pub,
			Type:             attest.AttestationType(c.Type),
			EvidenceHash:     c.EvHash,
			QuantumPublicKey: c.QPub,
		}
		canon := env.Canonical()
		out = append(out, envelopeCase{
			Name:             c.Name,
			ProducerID:       c.Pid,
			TimeNanos:        c.Time,
			Source:           c.Src,
			DataHex:          hex.EncodeToString(c.Data),
			PublicKeyHex:     hex.EncodeToString(pub),
			AttestationType:  c.Type,
			EvidenceHashHex:  hex.EncodeToString(c.EvHash),
			QuantumPublicKey: hex.EncodeToString(c.QPub),
			ExpectedCanonHex: hex.EncodeToString(canon),
			ExpectedHashHex:  hex.EncodeToString(sha256Sum(canon)),
		})
	}
	return out
}

func emitEnvelopeCanonical(path string) error {
	return writeJSON(path, map[string]any{
		"description": "Envelope.Canonical() byte-level outputs for cross-language SDK verification.",
		"format": "Inputs are hex-encoded. The expected_canonical_hex is the byte sequence the producer signs.",
		"cases": envelopeCases(),
	})
}

func emitEnvelopeHash(path string) error {
	cs := envelopeCases()
	mapped := make([]map[string]string, 0, len(cs))
	for _, c := range cs {
		mapped = append(mapped, map[string]string{
			"name":              c.Name,
			"canonical_hex":     c.ExpectedCanonHex,
			"expected_hash_hex": c.ExpectedHashHex,
		})
	}
	return writeJSON(path, map[string]any{
		"description": "Envelope.Hash() = SHA-256(canonical). Used by the operator's replay-protection table.",
		"cases":       mapped,
	})
}

func emitEnvelopeSigning(path string) error {
	// Deterministic seed for reproducible signatures.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	cases := []struct {
		Name string
		Src  string
		Data []byte
		Time int64
	}{
		{"deterministic_seed_0x42", "/var/log/x", []byte("first entry"), 1700000000000000000},
		{"empty_data", "/var/log/x", []byte{}, 1700000000000000000},
	}

	type sigCase struct {
		Name              string `json:"name"`
		SeedHex           string `json:"seed_hex"`
		PublicKeyHex      string `json:"public_key_hex"`
		ProducerID        string `json:"producer_id"`
		TimeNanos         int64  `json:"time_nanos"`
		Source            string `json:"source"`
		DataHex           string `json:"data_hex"`
		ExpectedCanonHex  string `json:"expected_canonical_hex"`
		ExpectedSigHex    string `json:"expected_signature_hex"`
	}

	out := make([]sigCase, 0, len(cases))
	for _, c := range cases {
		env := &attest.Envelope{
			ProducerID: "alice",
			TimeNanos:  c.Time,
			Source:     c.Src,
			Data:       c.Data,
			PublicKey:  pub,
			Type:       attest.TypeSoftware,
		}
		canon := env.Canonical()
		sig := ed25519.Sign(priv, canon)
		out = append(out, sigCase{
			Name:             c.Name,
			SeedHex:          hex.EncodeToString(seed),
			PublicKeyHex:     hex.EncodeToString(pub),
			ProducerID:       "alice",
			TimeNanos:        c.Time,
			Source:           c.Src,
			DataHex:          hex.EncodeToString(c.Data),
			ExpectedCanonHex: hex.EncodeToString(canon),
			ExpectedSigHex:   hex.EncodeToString(sig),
		})
	}
	return writeJSON(path, map[string]any{
		"description": "Full Ed25519-signed envelopes with a deterministic seed. SDKs reproduce these bit-for-bit.",
		"cases":       out,
	})
}

// --- Merkle vectors ---

type leafCase struct {
	Index       uint64 `json:"index"`
	DataHex     string `json:"data_hex"`
	LeafHashHex string `json:"leaf_hash_hex"`
}

func leafSeq(n int) [][]byte {
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 16)
		binary.BigEndian.PutUint64(b[:8], uint64(i))
		copy(b[8:], []byte("stele-tv"))
		out[i] = b
	}
	return out
}

func emitMerkleRoot(path string) error {
	type rootCase struct {
		TreeSize   int        `json:"tree_size"`
		Leaves     []leafCase `json:"leaves"`
		RootHashHex string    `json:"root_hash_hex"`
	}
	sizes := []int{0, 1, 2, 3, 4, 7, 8, 100}
	out := make([]rootCase, 0, len(sizes))
	for _, sz := range sizes {
		leaves := leafSeq(sz)
		tree := merkle.NewTree()
		var lc []leafCase
		for i, l := range leaves {
			h, _ := tree.AppendLeaf(l)
			lc = append(lc, leafCase{
				Index:       uint64(i),
				DataHex:     hex.EncodeToString(l),
				LeafHashHex: hex.EncodeToString(h),
			})
		}
		out = append(out, rootCase{
			TreeSize:    sz,
			Leaves:      lc,
			RootHashHex: hex.EncodeToString(tree.Root()),
		})
	}
	return writeJSON(path, map[string]any{
		"description": "RFC 6962 Merkle root over deterministic leaf sequences. Cross-implementations verify by re-deriving these roots.",
		"cases":       out,
	})
}

func emitMerkleInclusion(path string) error {
	type incCase struct {
		TreeSize int      `json:"tree_size"`
		LeafIdx  uint64   `json:"leaf_idx"`
		LeafHex  string   `json:"leaf_hex"`
		ProofHex []string `json:"proof_hex"`
		RootHex  string   `json:"root_hex"`
	}
	sizes := []int{8, 100, 1000}
	indices := []uint64{0, 4, 50, 999}
	out := []incCase{}
	for _, sz := range sizes {
		leaves := leafSeq(sz)
		tree := merkle.NewTree()
		for _, l := range leaves {
			tree.AppendLeaf(l)
		}
		root := tree.Root()
		for _, idx := range indices {
			if idx >= uint64(sz) {
				continue
			}
			prf, err := tree.InclusionProof(idx, uint64(sz))
			if err != nil {
				return err
			}
			proofHex := make([]string, len(prf))
			for i, n := range prf {
				proofHex[i] = hex.EncodeToString(n)
			}
			out = append(out, incCase{
				TreeSize: sz,
				LeafIdx:  idx,
				LeafHex:  hex.EncodeToString(leaves[idx]),
				ProofHex: proofHex,
				RootHex:  hex.EncodeToString(root),
			})
		}
	}
	return writeJSON(path, map[string]any{
		"description": "RFC 6962 inclusion proofs. Verifying: VerifyInclusion(idx, size, leaf_hash(leaf), proof, root) must return nil.",
		"cases":       out,
	})
}

func emitMerkleConsistency(path string) error {
	type conCase struct {
		OldSize  int      `json:"old_size"`
		NewSize  int      `json:"new_size"`
		OldRoot  string   `json:"old_root_hex"`
		NewRoot  string   `json:"new_root_hex"`
		ProofHex []string `json:"proof_hex"`
	}
	pairs := [][2]int{
		{0, 5},
		{1, 5},
		{3, 8},
		{8, 100},
		{50, 1000},
	}
	out := []conCase{}
	for _, p := range pairs {
		oldSz, newSz := p[0], p[1]
		leaves := leafSeq(newSz)

		oldTree := merkle.NewTree()
		for _, l := range leaves[:oldSz] {
			oldTree.AppendLeaf(l)
		}
		newTree := merkle.NewTree()
		for _, l := range leaves {
			newTree.AppendLeaf(l)
		}
		prf, err := newTree.ConsistencyProof(uint64(oldSz), uint64(newSz))
		if err != nil {
			return err
		}
		proofHex := make([]string, len(prf))
		for i, n := range prf {
			proofHex[i] = hex.EncodeToString(n)
		}
		out = append(out, conCase{
			OldSize:  oldSz,
			NewSize:  newSz,
			OldRoot:  hex.EncodeToString(oldTree.Root()),
			NewRoot:  hex.EncodeToString(newTree.Root()),
			ProofHex: proofHex,
		})
	}
	return writeJSON(path, map[string]any{
		"description": "RFC 6962 consistency proofs. VerifyConsistency(old_size, new_size, proof, old_root, new_root) must return nil.",
		"cases":       out,
	})
}

// --- checkpoint vectors ---

func emitCheckpointCanonical(path string) error {
	type ckCase struct {
		Name             string `json:"name"`
		Origin           string `json:"origin"`
		Size             uint64 `json:"size"`
		RootHashHex      string `json:"root_hash_hex"`
		HeadHashHex      string `json:"head_hash_hex"`
		TimeNanos        int64  `json:"time_nanos"`
		EpochIdx         uint64 `json:"epoch_idx"`
		KeyID            string `json:"key_id"`
		ExpectedCanonHex string `json:"expected_canonical_hex"`
	}
	root := make([]byte, 32)
	for i := range root {
		root[i] = 0xAB
	}
	head := make([]byte, 32)
	for i := range head {
		head[i] = 0xCD
	}
	cases := []struct {
		Name   string
		Origin string
		Size   uint64
		Time   int64
		Epoch  uint64
		KeyID  string
	}{
		{"minimal", "stele.local/log", 1, 1700000000000000000, 0, "abcdef0123456789"},
		{"size_1000", "example.com/audit", 1000, 1700000000000000000, 3, "0123456789abcdef"},
	}
	out := make([]ckCase, 0, len(cases))
	for _, c := range cases {
		ck := &checkpoint.Checkpoint{
			Origin:    c.Origin,
			Size:      c.Size,
			RootHash:  root,
			HeadHash:  head,
			TimeNanos: c.Time,
			EpochIdx:  c.Epoch,
			KeyID:     c.KeyID,
		}
		out = append(out, ckCase{
			Name:             c.Name,
			Origin:           c.Origin,
			Size:             c.Size,
			RootHashHex:      hex.EncodeToString(root),
			HeadHashHex:      hex.EncodeToString(head),
			TimeNanos:        c.Time,
			EpochIdx:         c.Epoch,
			KeyID:            c.KeyID,
			ExpectedCanonHex: hex.EncodeToString(ck.Canonical()),
		})
	}
	return writeJSON(path, map[string]any{
		"description": "Checkpoint.Canonical() bytes — what the operator's chain key signs over.",
		"cases":       out,
	})
}

// --- helpers ---

func emitIndexJSON(dir string) error {
	files := []string{
		"envelope_canonical.json",
		"envelope_hash.json",
		"envelope_signing.json",
		"merkle_root.json",
		"merkle_inclusion.json",
		"merkle_consistency.json",
		"checkpoint_canonical.json",
	}
	type idxEntry struct {
		File        string `json:"file"`
		Description string `json:"description"`
	}
	descs := map[string]string{
		"envelope_canonical.json":   "Envelope.Canonical() bytes for assorted shapes (classical, hybrid, unicode, large, empty).",
		"envelope_hash.json":        "Envelope.Hash() = SHA-256(canonical) for replay-protection table.",
		"envelope_signing.json":     "Deterministic Ed25519-signed envelopes (seed = 0x42 * 32).",
		"merkle_root.json":          "RFC 6962 root hashes over deterministic leaf sequences (sizes 0, 1, 2, 3, 4, 7, 8, 100).",
		"merkle_inclusion.json":     "RFC 6962 inclusion proofs at assorted (idx, size) pairs.",
		"merkle_consistency.json":   "RFC 6962 consistency proofs across (old, new) size pairs.",
		"checkpoint_canonical.json": "Checkpoint.Canonical() bytes (the operator-signed payload).",
	}
	entries := make([]idxEntry, 0, len(files))
	for _, f := range files {
		entries = append(entries, idxEntry{File: f, Description: descs[f]})
	}
	return writeJSON(filepath.Join(dir, "INDEX.json"), map[string]any{
		"description": "Stele cryptographic test vectors. SDKs in any language pass when they reproduce every expected_* field from the inputs.",
		"version":     "stele/v0.1.0",
		"files":       entries,
		"how_to_use": []string{
			"Each file lists deterministic inputs and expected outputs in hex.",
			"For each case: feed the inputs into your implementation; the bytes of the operation should match the expected output byte-for-byte.",
			"If your implementation's output differs by even one bit, your envelopes will be rejected by the reference operator.",
			"Auditors: re-run cmd/stele-vectors against the source and diff against this directory. Any difference is a finding.",
		},
	})
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o644)
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func bytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// io.Discard reference so importing io stays meaningful if we ever
// want to redirect output.
var _ = io.Discard
var _ = errors.New
