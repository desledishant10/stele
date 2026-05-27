package threshold

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"pgregory.net/rapid"
)

type signer struct {
	id   string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newSigners(t *rapid.T, n int) []signer {
	out := make([]signer, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		out[i] = signer{id: fmt.Sprintf("m%d", i), priv: priv, pub: pub}
	}
	return out
}

func makeGroup(signers []signer, threshold int) *Group {
	members := make([]*Member, len(signers))
	for i, s := range signers {
		members[i] = &Member{ID: s.id, PublicKey: append([]byte(nil), s.pub...)}
	}
	return &Group{
		Version:   1,
		Origin:    "prop-test",
		Members:   members,
		Threshold: uint32(threshold),
		CreatedAt: 1,
	}
}

func signWith(s signer, msg []byte) *MemberSig {
	return &MemberSig{
		MemberID:  s.id,
		PublicKey: append([]byte(nil), s.pub...),
		Signature: ed25519.Sign(s.priv, msg),
	}
}

// pickK returns k distinct indices from [0,n) using rapid choices.
func pickK(t *rapid.T, n, k int) []int {
	idxs := rapid.SliceOfNDistinct(rapid.IntRange(0, n-1), k, k, rapid.ID[int]).Draw(t, "pick")
	return idxs
}

// Any t valid signatures from distinct group members must verify.
func TestProp_AnyQuorumVerifies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 7).Draw(t, "n")
		threshold := rapid.IntRange(1, n).Draw(t, "t")
		signers := newSigners(t, n)
		g := makeGroup(signers, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "msg")

		// Pick exactly `threshold` distinct signers.
		picks := pickK(t, n, threshold)
		sigs := make([]*MemberSig, 0, threshold)
		for _, i := range picks {
			sigs = append(sigs, signWith(signers[i], msg))
		}
		if err := VerifyMulti(g, msg, sigs); err != nil {
			t.Fatalf("quorum of %d valid sigs failed: %v", threshold, err)
		}
	})
}

// Fewer than threshold valid sigs must fail.
func TestProp_BelowQuorumFails(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 7).Draw(t, "n")
		threshold := rapid.IntRange(2, n).Draw(t, "t")
		signers := newSigners(t, n)
		g := makeGroup(signers, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "msg")

		// Pick threshold-1 signers.
		picks := pickK(t, n, threshold-1)
		sigs := make([]*MemberSig, 0, threshold-1)
		for _, i := range picks {
			sigs = append(sigs, signWith(signers[i], msg))
		}
		if err := VerifyMulti(g, msg, sigs); err == nil {
			t.Fatalf("verified with only %d of %d sigs", threshold-1, threshold)
		}
	})
}

// Duplicate MemberSigs (same MemberID submitted twice) count only once
// — submitting the same signer K times with threshold > 1 must fail.
func TestProp_DuplicateSigsCountOnce(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 7).Draw(t, "n")
		threshold := rapid.IntRange(2, n).Draw(t, "t")
		signers := newSigners(t, n)
		g := makeGroup(signers, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "msg")

		// Submit the same signer (a valid one) `threshold` times.
		one := signWith(signers[0], msg)
		sigs := make([]*MemberSig, threshold)
		for i := range sigs {
			// Fresh copy each time so the slice doesn't alias.
			s := *one
			s.PublicKey = append([]byte(nil), one.PublicKey...)
			s.Signature = append([]byte(nil), one.Signature...)
			sigs[i] = &s
		}
		if err := VerifyMulti(g, msg, sigs); err == nil {
			t.Fatalf("verified with %d duplicate sigs (only 1 distinct member)", threshold)
		}
	})
}

// A foreign signer (someone outside the group) contributes 0 to the count.
// A quorum's worth of foreign signatures must NOT verify.
func TestProp_ForeignSignerRejected(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 5).Draw(t, "n")
		threshold := rapid.IntRange(1, n).Draw(t, "t")
		members := newSigners(t, n)
		g := makeGroup(members, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "msg")

		// Generate `threshold` outsiders, each labelled as a real member ID
		// but with a foreign key — substitution attempt.
		outsiders := newSigners(t, threshold)
		sigs := make([]*MemberSig, threshold)
		for i := 0; i < threshold; i++ {
			s := signWith(outsiders[i], msg)
			s.MemberID = members[i%n].id // pretend to be a real member
			sigs[i] = s
		}
		if err := VerifyMulti(g, msg, sigs); err == nil {
			t.Fatalf("verified with %d foreign signers impersonating group members", threshold)
		}
	})
}

// Adding garbage sigs on top of a valid quorum still verifies — VerifyMulti
// must skip invalid entries rather than abort.
func TestProp_GarbageDoesNotPoisonValidQuorum(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 6).Draw(t, "n")
		threshold := rapid.IntRange(1, n).Draw(t, "t")
		signers := newSigners(t, n)
		g := makeGroup(signers, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 0, 128).Draw(t, "msg")
		picks := pickK(t, n, threshold)
		valid := make([]*MemberSig, 0, threshold)
		for _, i := range picks {
			valid = append(valid, signWith(signers[i], msg))
		}

		// Garbage: a sig from an unknown member, a sig with a corrupted
		// signature, a nil entry.
		garbage1 := &MemberSig{
			MemberID:  "ghost",
			PublicKey: make([]byte, ed25519.PublicKeySize),
			Signature: make([]byte, ed25519.SignatureSize),
		}
		bad := signWith(signers[0], msg)
		bad.Signature[0] ^= 0xFF
		bad.MemberID = "ghost-2"
		all := append([]*MemberSig{nil, garbage1, bad}, valid...)
		// Shuffle order to make sure order-independence holds.
		rapid.Permutation(all).Draw(t, "perm")

		if err := VerifyMulti(g, msg, all); err != nil {
			t.Fatalf("valid quorum + garbage failed to verify: %v", err)
		}
	})
}

// Tampering with the message between sign and verify must always fail.
func TestProp_MessageTamperRejected(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 5).Draw(t, "n")
		threshold := rapid.IntRange(1, n).Draw(t, "t")
		signers := newSigners(t, n)
		g := makeGroup(signers, threshold)

		msg := rapid.SliceOfN(rapid.Byte(), 1, 128).Draw(t, "msg")
		picks := pickK(t, n, threshold)
		sigs := make([]*MemberSig, 0, threshold)
		for _, i := range picks {
			sigs = append(sigs, signWith(signers[i], msg))
		}
		// Flip a byte in the message.
		tampered := append([]byte(nil), msg...)
		bytePos := rapid.IntRange(0, len(tampered)-1).Draw(t, "byte")
		tampered[bytePos] ^= 0xFF
		if err := VerifyMulti(g, tampered, sigs); err == nil {
			t.Fatalf("verified with tampered message")
		}
	})
}
