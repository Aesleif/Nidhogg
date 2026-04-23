package transport

import (
	"crypto/ed25519"
	"testing"
)

func TestAuthStoreHasAndName(t *testing.T) {
	pubA, _, _ := GenerateKeypair()
	pubB, _, _ := GenerateKeypair()
	pubC, _, _ := GenerateKeypair() // not registered

	store := NewAuthStore(
		[]ed25519.PublicKey{pubA, pubB},
		[]string{"alice", "bob"},
	)

	if !store.Has(pubA) || store.Name(pubA) != "alice" {
		t.Errorf("pubA: Has=%v Name=%q", store.Has(pubA), store.Name(pubA))
	}
	if !store.Has(pubB) || store.Name(pubB) != "bob" {
		t.Errorf("pubB: Has=%v Name=%q", store.Has(pubB), store.Name(pubB))
	}
	if store.Has(pubC) {
		t.Error("pubC reported as authorized")
	}
	if n := store.Name(pubC); n != "" {
		t.Errorf("pubC name = %q, want empty", n)
	}
	if store.Size() != 2 {
		t.Errorf("Size = %d, want 2", store.Size())
	}
}

func TestAuthStoreHandlesShortNames(t *testing.T) {
	pubA, _, _ := GenerateKeypair()
	pubB, _, _ := GenerateKeypair()

	// names shorter than keys — missing entries must default to "".
	store := NewAuthStore(
		[]ed25519.PublicKey{pubA, pubB},
		[]string{"alice"},
	)
	if store.Name(pubA) != "alice" {
		t.Errorf("pubA name = %q", store.Name(pubA))
	}
	if store.Name(pubB) != "" {
		t.Errorf("pubB name = %q, want empty", store.Name(pubB))
	}
}

func TestAuthStoreDedupByKey(t *testing.T) {
	pubA, _, _ := GenerateKeypair()
	store := NewAuthStore(
		[]ed25519.PublicKey{pubA, pubA},
		[]string{"alice-v1", "alice-v2"},
	)
	if store.Size() != 1 {
		t.Errorf("duplicate key not collapsed: Size=%d", store.Size())
	}
	// Last write wins.
	if n := store.Name(pubA); n != "alice-v2" {
		t.Errorf("dedup name = %q, want alice-v2", n)
	}
}

func TestAuthStoreSkipsMalformedKeys(t *testing.T) {
	good, _, _ := GenerateKeypair()
	bad := ed25519.PublicKey{0x00, 0x01}

	store := NewAuthStore(
		[]ed25519.PublicKey{bad, good},
		[]string{"bad", "good"},
	)
	if store.Size() != 1 {
		t.Errorf("Size = %d, want 1", store.Size())
	}
	if !store.Has(good) {
		t.Error("good key missing")
	}
}
