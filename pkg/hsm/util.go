package hsm

import (
	"crypto/rand"
	"encoding/hex"
)

// randHex returns 16 hex characters of randomness, used to make PKCS#11
// labels unique within a token.
func randHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
