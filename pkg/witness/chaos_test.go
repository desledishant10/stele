package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// byzantineSeenServer is a mock peer that returns whatever SignedSeen
// the caller chooses, so we can simulate every "peer is lying" shape
// the gossip code is supposed to defend against.
type byzantineSeenServer struct {
	srv  *httptest.Server
	make func(origin string) *SignedSeen
}

func newByzantineSeenServer(t *testing.T, make func(origin string) *SignedSeen) *byzantineSeenServer {
	t.Helper()
	b := &byzantineSeenServer{make: make}
	mux := http.NewServeMux()
	mux.HandleFunc("/witness/v0/seen-signed", func(w http.ResponseWriter, r *http.Request) {
		origin := r.URL.Query().Get("origin")
		stmt := b.make(origin)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SignedSeenResponse{Statement: stmt})
	})
	// Also serve /checkpoint so CompareWithPeer's evidence-fetch
	// doesn't 404 (it can still find nothing — that's fine).
	mux.HandleFunc("/witness/v0/checkpoint", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	b.srv = httptest.NewServer(mux)
	return b
}

func (b *byzantineSeenServer) Close()        { b.srv.Close() }
func (b *byzantineSeenServer) URL() string   { return b.srv.URL }
func (b *byzantineSeenServer) Client() *http.Client { return b.srv.Client() }

// signSeen builds + signs a SignedSeen claiming a `seen` map signed by
// the given private key, with the given witness_id label. Used to
// fabricate "lying peer" responses in chaos tests.
func signSeen(t *testing.T, witnessID string, priv ed25519.PrivateKey, seen map[uint64]string) *SignedSeen {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	ss := &SignedSeen{
		WitnessID: witnessID,
		Origin:    "test.local/log",
		Seen:      seen,
		PublicKey: append([]byte(nil), pub...),
		IssuedAt:  time.Now().UnixNano(),
	}
	ss.Signature = ed25519.Sign(priv, ss.Canonical())
	return ss
}

// TestChaos_PeerSignsWithWrongKey: the peer responds with a perfectly
// valid SignedSeen — internally consistent, ed25519-verifiable — but
// signed by a key that does NOT match the registered peer pubkey. The
// honest witness must refuse to record the attestation.
func TestChaos_PeerSignsWithWrongKey(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")

	// The registered peer's REAL pubkey.
	realPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The attacker's pubkey (used to sign the response).
	_, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	root := []byte("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
	rootHex := hex.EncodeToString(root)

	byz := newByzantineSeenServer(t, func(origin string) *SignedSeen {
		return signSeen(t, "peer-X", attackerPriv, map[uint64]string{5: rootHex})
	})
	defer byz.Close()

	honest := newTestWitness(t, "honest-W")
	if err := honest.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	// Register the peer claiming its REAL pubkey, not the attacker's.
	if err := honest.AddPeer(&Peer{
		ID:        "peer-X",
		URL:       byz.URL(),
		PublicKey: realPub,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	honest.gossipRound(ctx, GossipConfig{HTTP: byz.Client(), Interval: time.Second})

	// The honest witness must NOT have recorded the attestation —
	// rejecting it specifically because the signing key doesn't match
	// the registered pubkey.
	if got := len(honest.PeerAttestations("peer-X")); got != 0 {
		t.Fatalf("attestation recorded for peer signed with wrong key (got %d)", got)
	}
	// Origin must NOT be flagged forked from this — the response was
	// noise, not honest contradictory evidence.
	if len(honest.ListForks()) != 0 {
		t.Fatal("byzantine wrong-key response should not create a fork claim")
	}
}

// TestChaos_PeerClaimsWrongWitnessID: the SignedSeen verifies, the key
// matches the registered peer, but the statement claims witness_id of
// a DIFFERENT peer. gossip.go explicitly rejects this — a peer that
// rebrands its statements could later be used to launder forged
// evidence into a victim peer's record.
func TestChaos_PeerClaimsWrongWitnessID(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := []byte("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
	rootHex := hex.EncodeToString(root)

	byz := newByzantineSeenServer(t, func(origin string) *SignedSeen {
		// Signed correctly, but claims to BE someone else.
		return signSeen(t, "some-other-witness", priv, map[uint64]string{5: rootHex})
	})
	defer byz.Close()

	honest := newTestWitness(t, "honest-W")
	if err := honest.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := honest.AddPeer(&Peer{
		ID:        "peer-X",
		URL:       byz.URL(),
		PublicKey: pub,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	honest.gossipRound(ctx, GossipConfig{HTTP: byz.Client(), Interval: time.Second})

	if got := len(honest.PeerAttestations("peer-X")); got != 0 {
		t.Fatalf("attestation recorded for peer claiming wrong witness_id (got %d)", got)
	}
}

// TestChaos_PeerBitFlipSignature: the statement is otherwise valid but
// the Signature field has been tampered with. Verify() rejects.
func TestChaos_PeerBitFlipSignature(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := []byte("RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
	rootHex := hex.EncodeToString(root)

	byz := newByzantineSeenServer(t, func(origin string) *SignedSeen {
		stmt := signSeen(t, "peer-X", priv, map[uint64]string{5: rootHex})
		stmt.Signature[0] ^= 0xFF
		return stmt
	})
	defer byz.Close()

	honest := newTestWitness(t, "honest-W")
	if err := honest.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := honest.AddPeer(&Peer{
		ID:        "peer-X",
		URL:       byz.URL(),
		PublicKey: pub,
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	honest.gossipRound(ctx, GossipConfig{HTTP: byz.Client(), Interval: time.Second})

	if got := len(honest.PeerAttestations("peer-X")); got != 0 {
		t.Fatalf("attestation recorded for peer with bit-flipped sig (got %d)", got)
	}
}

// TestChaos_PeerReturnsGarbage: the response isn't a SignedSeen at all
// — it's HTTP 500 garbage. gossip must skip cleanly.
func TestChaos_PeerReturnsGarbage(t *testing.T) {
	op, _ := newTestOperator(t, "test.local/log")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("BOOM"))
	}))
	defer srv.Close()

	honest := newTestWitness(t, "honest-W")
	if err := honest.AddOperator(&WatchedOperator{
		Origin:        "test.local/log",
		RootPublicKey: op.Chain().RootPublicKey(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := honest.AddPeer(&Peer{
		ID:        "peer-X",
		URL:       srv.URL,
		PublicKey: pub,
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	honest.gossipRound(ctx, GossipConfig{HTTP: srv.Client(), Interval: time.Second})
	if got := len(honest.PeerAttestations("peer-X")); got != 0 {
		t.Fatalf("garbage response shouldn't produce attestation (got %d)", got)
	}
}
