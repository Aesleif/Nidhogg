package transport

import (
	"crypto/ed25519"
)

// AuthStore holds the set of authorized client public keys.
// Constructed once at server startup from the "authorized_keys" config
// array (parsed by LoadConfig). Lookup is a constant-time map read;
// hot-reload is not supported in this version.
type AuthStore struct {
	keys map[[PubKeySize]byte]string // pubkey → optional operator-friendly name
}

// NewAuthStore builds an AuthStore from matched (key, name) slices.
// names may be shorter than keys; missing entries become "".
// Duplicate keys are silently collapsed — the last name wins.
func NewAuthStore(keys []ed25519.PublicKey, names []string) *AuthStore {
	s := &AuthStore{keys: make(map[[PubKeySize]byte]string, len(keys))}
	for i, k := range keys {
		if len(k) != PubKeySize {
			continue
		}
		var id [PubKeySize]byte
		copy(id[:], k)
		name := ""
		if i < len(names) {
			name = names[i]
		}
		s.keys[id] = name
	}
	return s
}

// Has reports whether pub is in the authorized set.
func (s *AuthStore) Has(pub ed25519.PublicKey) bool {
	if len(pub) != PubKeySize {
		return false
	}
	var id [PubKeySize]byte
	copy(id[:], pub)
	_, ok := s.keys[id]
	return ok
}

// Name returns the operator-assigned label for pub, or "" if absent.
// Intended for log lines; never include the pubkey bytes there to keep
// journals free of even-public identifiers.
func (s *AuthStore) Name(pub ed25519.PublicKey) string {
	if len(pub) != PubKeySize {
		return ""
	}
	var id [PubKeySize]byte
	copy(id[:], pub)
	return s.keys[id]
}

// Size returns the number of authorized keys — useful for startup logs.
func (s *AuthStore) Size() int {
	return len(s.keys)
}
