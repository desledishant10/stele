package trustdns

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
)

func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimSpace(s))
}

func encodeHex(b []byte) string {
	return hex.EncodeToString(b)
}
