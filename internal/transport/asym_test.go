package transport

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(pub) != PubKeySize {
		t.Errorf("pub len = %d, want %d", len(pub), PubKeySize)
	}
	if len(priv) != PrivKeySize {
		t.Errorf("priv len = %d, want %d", len(priv), PrivKeySize)
	}
}

func TestMarshalParseHello(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	buf := MarshalHello(pub)
	if len(buf) != HelloSize {
		t.Fatalf("hello size = %d, want %d", len(buf), HelloSize)
	}
	if buf[0] != AuthVersion {
		t.Errorf("version byte = %#x, want %#x", buf[0], AuthVersion)
	}

	got, err := ParseHello(buf)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("round-trip pubkey mismatch")
	}
}

func TestParseHelloErrors(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	good := MarshalHello(pub)

	if _, err := ParseHello(good[:HelloSize-1]); err == nil {
		t.Error("expected error on short buffer")
	}
	if _, err := ParseHello(append(good, 0)); err == nil {
		t.Error("expected error on long buffer")
	}

	bad := make([]byte, HelloSize)
	copy(bad, good)
	bad[0] = 0x01 // old PSK version
	if _, err := ParseHello(bad); err == nil {
		t.Error("expected error on wrong version")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}

	sig := SignChallenge(priv, nonce)
	if len(sig) != SignatureSize {
		t.Fatalf("sig len = %d, want %d", len(sig), SignatureSize)
	}
	if !VerifyChallenge(pub, nonce, sig) {
		t.Fatal("round-trip verification failed")
	}
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	nonce, _ := GenerateNonce()
	sig := SignChallenge(priv, nonce)

	// Flip a byte in the signature.
	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0xFF
	if VerifyChallenge(pub, nonce, bad) {
		t.Error("accepted tampered signature")
	}

	// Flip a byte in the nonce so the signed message differs.
	var otherNonce [NonceSize]byte = nonce
	otherNonce[0] ^= 0xFF
	if VerifyChallenge(pub, otherNonce, sig) {
		t.Error("accepted signature over different nonce")
	}

	// Another keypair's pubkey must not verify.
	otherPub, _, _ := GenerateKeypair()
	if VerifyChallenge(otherPub, nonce, sig) {
		t.Error("accepted signature against different pubkey")
	}
}

func TestVerifyRejectsMalformedInputs(t *testing.T) {
	pub, priv, _ := GenerateKeypair()
	nonce, _ := GenerateNonce()
	sig := SignChallenge(priv, nonce)

	if VerifyChallenge(ed25519.PublicKey{}, nonce, sig) {
		t.Error("accepted empty pubkey")
	}
	if VerifyChallenge(pub, nonce, sig[:len(sig)-1]) {
		t.Error("accepted short signature")
	}
}
