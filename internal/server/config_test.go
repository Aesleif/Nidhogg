package server

import (
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

func TestLoadConfig_Full(t *testing.T) {
	path := writeTestConfig(t, `{
		"listen": ":8443",
		"domain": "shop.example.com",
		"psk": "secret-key",
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
	if cfg.PSK != "secret-key" {
		t.Errorf("PSK = %q, want %q", cfg.PSK, "secret-key")
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
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"psk": "key",
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

func TestLoadConfig_MissingPSK(t *testing.T) {
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"cover_upstream": "www.microsoft.com:443"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing PSK")
	}
}

func TestLoadConfig_MissingCoverUpstream(t *testing.T) {
	path := writeTestConfig(t, `{
		"domain": "example.com",
		"psk": "key"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing cover_upstream")
	}
}

func TestLoadConfig_MissingDomainWithoutCert(t *testing.T) {
	path := writeTestConfig(t, `{
		"psk": "key",
		"cover_upstream": "www.microsoft.com:443"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing domain when cert_file not set")
	}
}

func TestLoadConfig_CertWithoutKey(t *testing.T) {
	path := writeTestConfig(t, `{
		"psk": "key",
		"cover_upstream": "www.microsoft.com:443",
		"cert_file": "cert.pem"
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error when cert_file set without key_file")
	}
}

func TestLoadConfig_CertFileAllowsMissingDomain(t *testing.T) {
	path := writeTestConfig(t, `{
		"psk": "key",
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
