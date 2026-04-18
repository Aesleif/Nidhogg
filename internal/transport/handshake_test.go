package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func TestGenerateAndValidate(t *testing.T) {
	psk := []byte("test-secret-key")
	v := NewValidator(psk)

	data, err := GenerateHandshake(psk)
	if err != nil {
		t.Fatalf("GenerateHandshake: %v", err)
	}
	if len(data) != HandshakeSize {
		t.Fatalf("len = %d, want %d", len(data), HandshakeSize)
	}

	ok, err := v.Validate(data)
	if !ok || err != nil {
		t.Fatalf("Validate: ok=%v, err=%v", ok, err)
	}
}

func TestTamperedByte(t *testing.T) {
	psk := []byte("test-secret-key")
	v := NewValidator(psk)

	data, _ := GenerateHandshake(psk)
	data[15] ^= 0xFF // flip a byte in nonce region

	ok, err := v.Validate(data)
	if ok {
		t.Fatal("expected validation to fail with tampered data")
	}
	if err == nil || err.Error() != "HMAC mismatch" {
		t.Fatalf("expected HMAC mismatch error, got: %v", err)
	}
}

func TestReplayNonce(t *testing.T) {
	psk := []byte("test-secret-key")
	v := NewValidator(psk)

	data, _ := GenerateHandshake(psk)

	ok, _ := v.Validate(data)
	if !ok {
		t.Fatal("first validation should pass")
	}

	ok, err := v.Validate(data)
	if ok {
		t.Fatal("replay should be rejected")
	}
	if err == nil || err.Error() != "nonce reused" {
		t.Fatalf("expected nonce reused error, got: %v", err)
	}
}

func TestExpiredTimestamp(t *testing.T) {
	psk := []byte("test-secret-key")
	v := NewValidator(psk)
	v.now = func() time.Time {
		return time.Now().Add(120 * time.Second) // 120s in the future relative to marker
	}

	data, _ := GenerateHandshake(psk) // generated with real time.Now

	ok, err := v.Validate(data)
	if ok {
		t.Fatal("expired timestamp should be rejected")
	}
	if err == nil || err.Error() != "timestamp out of range" {
		t.Fatalf("expected timestamp error, got: %v", err)
	}
}

func TestFutureTimestamp(t *testing.T) {
	psk := []byte("test-secret-key")
	v := NewValidator(psk)
	v.now = func() time.Time {
		return time.Now().Add(-120 * time.Second) // 120s in the past relative to marker
	}

	data, _ := GenerateHandshake(psk)

	ok, err := v.Validate(data)
	if ok {
		t.Fatal("future timestamp should be rejected")
	}
	if err == nil || err.Error() != "timestamp out of range" {
		t.Fatalf("expected timestamp error, got: %v", err)
	}
}

func TestWrongPSK(t *testing.T) {
	data, _ := GenerateHandshake([]byte("psk-aaa"))
	v := NewValidator([]byte("psk-bbb"))

	ok, err := v.Validate(data)
	if ok {
		t.Fatal("wrong PSK should be rejected")
	}
	if err == nil || err.Error() != "HMAC mismatch" {
		t.Fatalf("expected HMAC mismatch, got: %v", err)
	}
}

func TestShortData(t *testing.T) {
	v := NewValidator([]byte("key"))

	ok, err := v.Validate([]byte("short"))
	if ok {
		t.Fatal("short data should be rejected")
	}
	if err == nil || err.Error() != "invalid handshake size" {
		t.Fatalf("expected size error, got: %v", err)
	}
}

func TestWrongVersion(t *testing.T) {
	psk := []byte("test-key")
	data, _ := GenerateHandshake(psk)

	// Change version and recompute HMAC
	data[0] = 0x02
	mac := hmac.New(sha256.New, psk)
	mac.Write(data[0:25])
	copy(data[25:57], mac.Sum(nil))

	v := NewValidator(psk)
	ok, err := v.Validate(data)
	if ok {
		t.Fatal("wrong version should be rejected")
	}
	if err == nil || err.Error() != "unsupported version" {
		t.Fatalf("expected version error, got: %v", err)
	}
}

func TestNonceTimeEviction(t *testing.T) {
	psk := []byte("ring-test-key")
	v := NewValidator(psk)

	baseTime := time.Now()
	v.now = func() time.Time { return baseTime }

	// Validate first handshake
	first, _ := GenerateHandshake(psk)
	ok, _ := v.Validate(first)
	if !ok {
		t.Fatal("first handshake should pass")
	}

	// Replay should be rejected while nonce is in the map
	ok, err := v.Validate(first)
	if ok {
		t.Fatal("immediate replay should be rejected")
	}
	if err.Error() != "nonce reused" {
		t.Fatalf("expected nonce reused, got: %v", err)
	}

	// Fill past nonceRingSize to trigger eviction sweep
	for i := 0; i < nonceRingSize+1; i++ {
		data, _ := GenerateHandshake(psk)
		v.Validate(data)
	}

	// Advance time past 2*maxClockSkew so old nonces expire
	v.now = func() time.Time { return baseTime.Add(3 * maxClockSkew) }

	// Insert one more to trigger eviction of expired entries
	trigger, _ := GenerateHandshake(psk)
	// Fix timestamp to match the new "now"
	binary.BigEndian.PutUint64(trigger[1:9], uint64(v.now().UnixMilli()))
	mac := hmac.New(sha256.New, psk)
	mac.Write(trigger[0:25])
	copy(trigger[25:57], mac.Sum(nil))
	v.Validate(trigger)

	// Now reuse the first nonce with a fresh timestamp — should be accepted
	fresh, _ := GenerateHandshake(psk)
	copy(fresh[9:25], first[9:25]) // reuse nonce from first
	binary.BigEndian.PutUint64(fresh[1:9], uint64(v.now().UnixMilli()))
	mac = hmac.New(sha256.New, psk)
	mac.Write(fresh[0:25])
	copy(fresh[25:57], mac.Sum(nil))

	ok, err = v.Validate(fresh)
	if !ok {
		t.Fatalf("evicted nonce should be accepted, got: %v", err)
	}
}

func TestConcurrentValidation(t *testing.T) {
	psk := []byte("concurrent-key")
	v := NewValidator(psk)

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := GenerateHandshake(psk)
			if err != nil {
				errors <- err
				return
			}
			ok, err := v.Validate(data)
			if !ok {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent validation error: %v", err)
	}
}

func TestHandshakeFormat(t *testing.T) {
	psk := []byte("format-key")
	data, _ := GenerateHandshake(psk)

	if data[0] != versionV1 {
		t.Errorf("version = %d, want %d", data[0], versionV1)
	}

	tsMs := binary.BigEndian.Uint64(data[1:9])
	ts := time.UnixMilli(int64(tsMs))
	if time.Since(ts) > 5*time.Second {
		t.Error("timestamp too far from now")
	}
}
