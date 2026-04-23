package server

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

// samplePubKeyB64 returns a valid base64-encoded Ed25519 public key so
// tests can populate authorized_keys without computing one by hand.
func samplePubKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func TestLoadConfig_Full(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"listen": ":8443",
		"domain": "shop.example.com",
		"authorized_keys": ["`+pubB64+` alice"],
		"cover_upstream": "real-shop.com:443",
		"tunnel_path": "/upload",
		"cert_file": "cert.pem",
		"key_file": "key.pem"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != ":8443" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":8443")
	}
	if cfg.Domain != "shop.example.com" {
		t.Errorf("Domain = %q, want %q", cfg.Domain, "shop.example.com")
	}
	if len(cfg.AuthorizedKeys) != 1 {
		t.Fatalf("AuthorizedKeys len = %d, want 1", len(cfg.AuthorizedKeys))
	}
	keys, names, err := cfg.ParsedAuthorizedKeys()
	if err != nil {
		t.Fatalf("ParsedAuthorizedKeys: %v", err)
	}
	if len(keys) != 1 || names[0] != "alice" {
		t.Errorf("parsed keys = %d names[0]=%q, want 1 alice", len(keys), names[0])
	}
	if cfg.CoverUpstream != "real-shop.com:443" {
		t.Errorf("CoverUpstream = %q, want %q", cfg.CoverUpstream, "real-shop.com:443")
	}
	if cfg.TunnelPath != "/upload" {
		t.Errorf("TunnelPath = %q, want %q", cfg.TunnelPath, "/upload")
	}
	if cfg.CertFile != "cert.pem" {
		t.Errorf("CertFile = %q, want %q", cfg.CertFile, "cert.pem")
	}
	if cfg.KeyFile != "key.pem" {
		t.Errorf("KeyFile = %q, want %q", cfg.KeyFile, "key.pem")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"authorized_keys": ["`+pubB64+`"],
		"cover_upstream": "www.microsoft.com:443"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != ":443" {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, ":443")
	}
	if cfg.TunnelPath != "/" {
		t.Errorf("TunnelPath = %q, want default %q", cfg.TunnelPath, "/")
	}
}

func TestLoadConfig_MissingAuthorizedKeys(t *testing.T) {
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"cover_upstream": "www.microsoft.com:443"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing authorized_keys")
	}
}

func TestLoadConfig_InvalidAuthorizedKey(t *testing.T) {
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"authorized_keys": ["not-base64!!"],
		"cover_upstream": "www.microsoft.com:443"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestLoadConfig_MissingCoverUpstream(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"authorized_keys": ["`+pubB64+`"]
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing cover_upstream")
	}
}

func TestLoadConfig_MissingDomainWithoutCert(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"authorized_keys": ["`+pubB64+`"],
		"cover_upstream": "www.microsoft.com:443"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing domain when cert_file not set")
	}
}

func TestLoadConfig_CertWithoutKey(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"authorized_keys": ["`+pubB64+`"],
		"cover_upstream": "www.microsoft.com:443",
		"cert_file": "cert.pem"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error when cert_file set without key_file")
	}
}

func TestLoadConfig_CertFileAllowsMissingDomain(t *testing.T) {
	pubB64 := samplePubKeyB64(t)
	path := writeTestConfig(t, `{
		"authorized_keys": ["`+pubB64+`"],
		"cover_upstream": "www.microsoft.com:443",
		"cert_file": "cert.pem",
		"key_file": "key.pem"
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Domain != "" {
		t.Errorf("Domain = %q, want empty", cfg.Domain)
	}
}
