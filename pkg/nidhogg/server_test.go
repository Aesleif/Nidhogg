package nidhogg_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/aesleif/nidhogg/pkg/nidhogg"
)

func genPubKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

func TestNewServerValidation(t *testing.T) {
	_, err := nidhogg.NewServer(nidhogg.ServerConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}

	_, err = nidhogg.NewServer(nidhogg.ServerConfig{
		AuthorizedKeys: []ed25519.PublicKey{genPubKey(t)},
	})
	if err == nil {
		t.Fatal("expected error for missing CoverUpstream")
	}

	srv, err := nidhogg.NewServer(nidhogg.ServerConfig{
		AuthorizedKeys: []ed25519.PublicKey{genPubKey(t)},
		CoverUpstream:  "www.microsoft.com:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.Close()

	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestNewServerDefaults(t *testing.T) {
	srv, err := nidhogg.NewServer(nidhogg.ServerConfig{
		AuthorizedKeys: []ed25519.PublicKey{genPubKey(t)},
		CoverUpstream:  "www.microsoft.com:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.Close()

	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestNewServerInvalidCoverUpstream(t *testing.T) {
	// Missing :port — net.SplitHostPort rejects.
	_, err := nidhogg.NewServer(nidhogg.ServerConfig{
		AuthorizedKeys: []ed25519.PublicKey{genPubKey(t)},
		CoverUpstream:  "no-port-here",
	})
	if err == nil {
		t.Fatal("expected error for CoverUpstream without :port")
	}
}
