//go:build cgo

package hsm

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/desledishant10/stele/pkg/fwdsec"
)

// Most tests in this package require a real PKCS#11 module + slot. We
// drive them via env vars:
//
//   STELE_HSM_MODULE   path to libsofthsm2.so or similar
//   STELE_HSM_SLOT     slot ID (decimal)
//   STELE_HSM_PIN      user PIN
//
// The build pipeline / CI is expected to set these via softhsm2-util.
// If they're unset, the tests skip rather than fail — so `go test ./...`
// still works on machines without an HSM.
func cfgFromEnv(t *testing.T) Config {
	t.Helper()
	mod := os.Getenv("STELE_HSM_MODULE")
	slotStr := os.Getenv("STELE_HSM_SLOT")
	pin := os.Getenv("STELE_HSM_PIN")
	if mod == "" || slotStr == "" || pin == "" {
		t.Skip("HSM env vars not set; skipping PKCS#11 integration test")
	}
	slot, err := strconv.ParseUint(slotStr, 10, 32)
	if err != nil {
		t.Fatalf("bad STELE_HSM_SLOT: %v", err)
	}
	return Config{
		Module:    mod,
		SlotID:    uint(slot),
		PIN:       pin,
		KeyPrefix: "stele-test-" + strings.ToLower(t.Name()),
	}
}

// cleanup destroys any keys this test left behind so the next test run
// starts from a clean slate.
func cleanup(t *testing.T, store *PKCS11KeyStore, locator string) {
	t.Helper()
	if locator == "" {
		return
	}
	key, err := store.Load(locator)
	if err != nil {
		// Already gone — fine.
		return
	}
	_ = key.Destroy()
}

func TestOpenSignDestroy(t *testing.T) {
	store, err := Open(cfgFromEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key, err := store.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup(t, store, key.Locator())

	if len(key.Public()) != ed25519.PublicKeySize {
		t.Fatalf("bad pubkey length %d", len(key.Public()))
	}

	msg := []byte("hello from stele")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public(), msg, sig) {
		t.Fatal("HSM signature did not verify against returned public key")
	}

	if err := key.Destroy(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(key.Locator()); err == nil {
		t.Fatal("Load should fail after Destroy")
	}
}

func TestLoadAfterReopen(t *testing.T) {
	cfg := cfgFromEnv(t)

	store1, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	key, err := store1.Generate()
	if err != nil {
		store1.Close()
		t.Fatal(err)
	}
	locator := key.Locator()
	expectedPub := append([]byte(nil), key.Public()...)
	if err := store1.Close(); err != nil {
		t.Fatal(err)
	}

	store2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	defer cleanup(t, store2, locator)

	reopened, err := store2.Load(locator)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ed25519.PublicKey(reopened.Public()).Equal(ed25519.PublicKey(expectedPub)) {
		t.Fatal("reopened public key does not match the original")
	}
	// And signing must still work.
	sig, err := reopened.Sign([]byte("after-reopen"))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(reopened.Public(), []byte("after-reopen"), sig) {
		t.Fatal("signature failed verification after reopen")
	}
}

// End-to-end test: stele's full forward-secure Signer flow against an
// HSM-backed key store. Exercises createGenesis, Sign, Rotate, Close,
// reopen via fwdsec.NewSignerWithStore.
func TestForwardSecureSignerWithHSM(t *testing.T) {
	cfg := cfgFromEnv(t)
	dir := t.TempDir()

	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := fwdsec.NewSignerWithStore("hsm-test", dir, store)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}

	// Sign something in epoch 0.
	msg := []byte("epoch-0 message")
	epoch0, sig0, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if epoch0 != 0 {
		t.Fatalf("expected epoch 0, got %d", epoch0)
	}
	pub0 := s.Chain().PublicKeyAt(0)
	if !ed25519.Verify(pub0, msg, sig0) {
		t.Fatal("epoch 0 HSM signature did not verify")
	}

	// Rotate to epoch 1.
	cert, err := s.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Epoch != 1 {
		t.Fatalf("expected new cert epoch 1, got %d", cert.Epoch)
	}

	// Old key should now be destroyed; old signature still verifies
	// against the chain's old public key.
	if !ed25519.Verify(pub0, msg, sig0) {
		t.Fatal("pre-rotation signature should still verify")
	}

	// New epoch signs.
	msg2 := []byte("epoch-1 message")
	epoch1, sig1, err := s.Sign(msg2)
	if err != nil {
		t.Fatal(err)
	}
	if epoch1 != 1 {
		t.Fatalf("expected epoch 1, got %d", epoch1)
	}
	pub1 := s.Chain().PublicKeyAt(1)
	if !ed25519.Verify(pub1, msg2, sig1) {
		t.Fatal("epoch 1 HSM signature did not verify")
	}

	// Chain must validate.
	if err := s.Chain().VerifyChain(s.RootPublicKey()); err != nil {
		t.Fatalf("chain invalid: %v", err)
	}

	// Re-open: persistence and locator-based key load.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	store2, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	s2, err := fwdsec.NewSignerWithStore("hsm-test", dir, store2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if s2.ActiveEpoch() != 1 {
		t.Fatalf("expected reopened active epoch 1, got %d", s2.ActiveEpoch())
	}
	if err := s2.Chain().VerifyChain(s2.RootPublicKey()); err != nil {
		t.Fatalf("reopened chain invalid: %v", err)
	}

	// Cleanup: destroy the active key so the SoftHSM token doesn't grow
	// unboundedly across test runs.
	active, err := store2.Load(s2.Chain().ActiveLocator)
	if err == nil {
		_ = active.Destroy()
	}
}

// noKeyOnDisk verifies that with the HSM store, the operator's data
// directory contains chain.json but no .key files. (The whole point of
// the upgrade.)
func TestNoPrivateKeyMaterialOnDisk(t *testing.T) {
	cfg := cfgFromEnv(t)
	dir := t.TempDir()

	store, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	s, err := fwdsec.NewSignerWithStore("hsm-test", dir, store)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, _, err := s.Sign([]byte("x")); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".key") {
			t.Fatalf("found .key file under operator dir: %s", filepath.Join(dir, e.Name()))
		}
	}

	// Cleanup HSM-side key.
	active, err := store.Load(s.Chain().ActiveLocator)
	if err == nil {
		_ = active.Destroy()
	}
}
