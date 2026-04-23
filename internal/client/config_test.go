package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// samplePrivKeyB64 returns a valid base64-encoded Ed25519 private key
// (64-byte seed||pubkey). Used to populate the private_key config field.
func samplePrivKeyB64(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(priv)
}

func TestLoadConfig_Full(t *testing.T) {
	privB64 := samplePrivKeyB64(t)
	path := writeTestConfig(t, `{
		"server": "shop.example.com:443",
		"private_key": "`+privB64+`",
		"listen": "127.0.0.1:9090",
		"tunnel_path": "/upload"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server != "shop.example.com:443" {
		t.Errorf("Server = %q, want %q", cfg.Server, "shop.example.com:443")
	}
	priv, err := cfg.PrivateKeyBytes()
	if err != nil {
		t.Fatalf("PrivateKeyBytes: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv len = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, "127.0.0.1:9090")
	}
	if cfg.TunnelPath != "/upload" {
		t.Errorf("TunnelPath = %q, want %q", cfg.TunnelPath, "/upload")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	privB64 := samplePrivKeyB64(t)
	path := writeTestConfig(t, `{
		"server": "example.com:443",
		"private_key": "`+privB64+`"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1080" {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, "127.0.0.1:1080")
	}
	if cfg.TunnelPath != "/" {
		t.Errorf("TunnelPath = %q, want default %q", cfg.TunnelPath, "/")
	}
}

func TestLoadConfig_MissingServer(t *testing.T) {
	path := writeTestConfig(t, `{"private_key": "`+samplePrivKeyB64(t)+`"}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for missing server")
	}
}

func TestLoadConfig_MissingPrivateKey(t *testing.T) {
	path := writeTestConfig(t, `{"server": "example.com:443"}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for missing private_key")
	}
}

func TestLoadConfig_InvalidPrivateKey(t *testing.T) {
	path := writeTestConfig(t, `{
		"server": "example.com:443",
		"private_key": "not-base64!!"
	}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for bad base64 private_key")
	}
}
