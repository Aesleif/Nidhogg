package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// AuthVersion is the protocol version byte for Ed25519 auth.
	// Reserved: 0x01 was the old HMAC-PSK handshake.
	AuthVersion = 0x02

	// PubKeySize is the length of an Ed25519 public key in bytes.
	PubKeySize = ed25519.PublicKeySize

	// PrivKeySize is the length of an Ed25519 private key in bytes
	// (seed || public key).
	PrivKeySize = ed25519.PrivateKeySize

	// NonceSize is the length of the server-issued challenge nonce.
	NonceSize = 32

	// SignatureSize is the length of an Ed25519 signature in bytes.
	SignatureSize = ed25519.SignatureSize

	// HelloSize is the length of the client's hello on the wire:
	// [version:1][pubkey:32].
	HelloSize = 1 + PubKeySize
)

// authContext is a domain-separation tag mixed into the signed message.
// It prevents a signature from being reused in another protocol that
// happens to feed raw nonces to the same key.
var authContext = []byte("nidhogg-auth-v2\x00")

// GenerateKeypair creates a new Ed25519 keypair via crypto/rand.
func GenerateKeypair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalHello encodes the client's hello segment: [version:1][pubkey:32].
func MarshalHello(pub ed25519.PublicKey) []byte {
	if len(pub) != PubKeySize {
		// Defensive: a malformed public key here is a programmer error,
		// not a wire event. Panic surfaces it immediately in tests.
		panic(fmt.Sprintf("transport: bad pubkey length %d", len(pub)))
	}
	out := make([]byte, HelloSize)
	out[0] = AuthVersion
	copy(out[1:], pub)
	return out
}

// ParseHello reads a hello buffer and returns the claimed public key.
// Errors are reported without distinguishing causes — callers that see
// a ParseHello error should fall back to the cover-site proxy so the
// failure is indistinguishable from any other non-nidhogg request.
func ParseHello(data []byte) (ed25519.PublicKey, error) {
	if len(data) != HelloSize {
		return nil, errors.New("invalid hello size")
	}
	if data[0] != AuthVersion {
		return nil, errors.New("unsupported auth version")
	}
	pub := make(ed25519.PublicKey, PubKeySize)
	copy(pub, data[1:])
	return pub, nil
}

// GenerateNonce returns a cryptographically random 32-byte challenge.
func GenerateNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("nonce: %w", err)
	}
	return nonce, nil
}

// SignChallenge signs authContext || nonce with priv.
func SignChallenge(priv ed25519.PrivateKey, nonce [NonceSize]byte) []byte {
	msg := make([]byte, 0, len(authContext)+NonceSize)
	msg = append(msg, authContext...)
	msg = append(msg, nonce[:]...)
	return ed25519.Sign(priv, msg)
}

// VerifyChallenge verifies sig over authContext || nonce against pub.
// Returns false for any malformed input or bad signature.
func VerifyChallenge(pub ed25519.PublicKey, nonce [NonceSize]byte, sig []byte) bool {
	if len(pub) != PubKeySize || len(sig) != SignatureSize {
		return false
	}
	msg := make([]byte, 0, len(authContext)+NonceSize)
	msg = append(msg, authContext...)
	msg = append(msg, nonce[:]...)
	return ed25519.Verify(pub, msg, sig)
}
