package server

import (
	"crypto/subtle"
	"io"
)

// ReadAndCheckPSK reads len(psk) bytes from body and compares them
// to psk using constant-time comparison.
// Returns true if PSK matches, false otherwise.
// On read error (e.g. body too short), returns false.
func ReadAndCheckPSK(body io.Reader, psk []byte) bool {
	buf := make([]byte, len(psk))
	if _, err := io.ReadFull(body, buf); err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(buf, psk) == 1
}
