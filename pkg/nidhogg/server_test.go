package nidhogg_test

import (
	"testing"

	"github.com/aesleif/nidhogg/pkg/nidhogg"
)

func TestNewServerValidation(t *testing.T) {
	_, err := nidhogg.NewServer(nidhogg.ServerConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}

	_, err = nidhogg.NewServer(nidhogg.ServerConfig{PSK: "secret"})
	if err == nil {
		t.Fatal("expected error for missing ProxyTo")
	}

	srv, err := nidhogg.NewServer(nidhogg.ServerConfig{
		PSK:     "secret",
		ProxyTo: "https://example.com",
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
		PSK:     "secret",
		ProxyTo: "https://example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer srv.Close()

	if srv.Handler() == nil {
		t.Fatal("Handler() returned nil")
	}
}

func TestNewServerInvalidProxyTo(t *testing.T) {
	_, err := nidhogg.NewServer(nidhogg.ServerConfig{
		PSK:     "secret",
		ProxyTo: "://invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid ProxyTo URL")
	}
}
