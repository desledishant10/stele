//go:build !cgo

// This is the no-cgo stub of pkg/hsm. The real PKCS#11 binding lives
// in pkcs11.go behind `//go:build cgo` because miekg/pkcs11 uses cgo
// to call the C PKCS#11 module API.
//
// In a no-cgo build (e.g. our reproducible release / chaos rig
// containers), HSM mode is simply not available — Open returns a
// clear error so steled --hsm-module fails fast at startup rather
// than silently falling through to the file-backed keystore.
//
// To enable HSM support, build with CGO_ENABLED=1 (the default on
// most Linux distros).
package hsm

import (
	"errors"

	"github.com/desledishant10/stele/pkg/fwdsec"
)

// Config mirrors the cgo build's Config so calling code compiles
// unchanged. Only the fields steled reads are kept.
type Config struct {
	Module    string
	SlotID    uint
	PIN       string
	KeyPrefix string
}

// PKCS11KeyStore is a placeholder type for compile-time symmetry.
// All methods would error if reachable; in practice Open below
// short-circuits before any method is called.
type PKCS11KeyStore struct{}

// Open always errors in a no-cgo build. The error message points the
// operator at a CGO_ENABLED=1 rebuild.
func Open(cfg Config) (*PKCS11KeyStore, error) {
	return nil, errors.New("hsm: PKCS#11 support not compiled in (build with CGO_ENABLED=1 to enable --hsm-module)")
}

// Close is a no-op so steled's deferred shutdown works regardless.
func (s *PKCS11KeyStore) Close() error { return nil }

// Generate / Load are unreachable in practice but defined for symmetry.
func (s *PKCS11KeyStore) Generate() (fwdsec.LiveKey, error) {
	return nil, errors.New("hsm: no-cgo build cannot generate HSM keys")
}

func (s *PKCS11KeyStore) Load(locator string) (fwdsec.LiveKey, error) {
	return nil, errors.New("hsm: no-cgo build cannot load HSM keys")
}
