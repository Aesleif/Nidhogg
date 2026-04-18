package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	HandshakeSize = 57
	versionV1     = 0x01
	nonceSize     = 16
	nonceRingSize = 10000
	maxClockSkew  = 60 * time.Second
)

// GenerateHandshake creates a 57-byte handshake marker.
// Format: [version:1][timestamp:8][nonce:16][hmac:32]
func GenerateHandshake(psk []byte) ([]byte, error) {
	buf := make([]byte, HandshakeSize)

	buf[0] = versionV1
	binary.BigEndian.PutUint64(buf[1:9], uint64(time.Now().UnixMilli()))

	if _, err := rand.Read(buf[9:25]); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, psk)
	mac.Write(buf[0:25])
	copy(buf[25:57], mac.Sum(nil))

	return buf, nil
}

// HandshakeValidator validates handshake markers on the server side.
// It is safe for concurrent use.
type HandshakeValidator struct {
	psk    []byte
	nonces map[[nonceSize]byte]int64 // nonce → timestamp_ms
	mu     sync.Mutex
	now    func() time.Time
}

// NewValidator creates a new HandshakeValidator with the given PSK.
func NewValidator(psk []byte) *HandshakeValidator {
	return &HandshakeValidator{
		psk:    psk,
		nonces: make(map[[nonceSize]byte]int64),
		now:    time.Now,
	}
}

// Validate checks a 57-byte handshake marker.
// Returns (true, nil) if valid, (false, error) with reason otherwise.
// Validation order: size → version → timestamp → HMAC → nonce replay.
// HMAC is checked before nonce to prevent attackers from filling the
// ring buffer with junk nonces.
func (v *HandshakeValidator) Validate(data []byte) (bool, error) {
	if len(data) != HandshakeSize {
		return false, errors.New("invalid handshake size")
	}

	if data[0] != versionV1 {
		return false, errors.New("unsupported version")
	}

	tsMs := binary.BigEndian.Uint64(data[1:9])
	ts := time.UnixMilli(int64(tsMs))
	now := v.now()
	diff := now.Sub(ts)
	if diff < 0 {
		diff = -diff
	}
	if diff > maxClockSkew {
		return false, errors.New("timestamp out of range")
	}

	mac := hmac.New(sha256.New, v.psk)
	mac.Write(data[0:25])
	expected := mac.Sum(nil)
	if !hmac.Equal(data[25:57], expected) {
		return false, errors.New("HMAC mismatch")
	}

	// Check nonce replay (O(1) map lookup)
	var nonce [nonceSize]byte
	copy(nonce[:], data[9:25])

	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.nonces[nonce]; exists {
		return false, errors.New("nonce reused")
	}

	v.nonces[nonce] = int64(tsMs)

	// Evict expired nonces when map grows too large
	if len(v.nonces) > nonceRingSize {
		cutoff := v.now().Add(-2 * maxClockSkew).UnixMilli()
		for k, ts := range v.nonces {
			if ts < cutoff {
				delete(v.nonces, k)
			}
		}
	}

	return true, nil
}
