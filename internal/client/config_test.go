package client

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
		"server": "shop.example.com:443",
		"psk": "secret-key",
		"listen": "127.0.0.1:9090",
		"tunnel_path": "/upload",
		"insecure": true
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server != "shop.example.com:443" {
		t.Errorf("Server = %q, want %q", cfg.Server, "shop.example.com:443")
	}
	if cfg.PSK != "secret-key" {
		t.Errorf("PSK = %q, want %q", cfg.PSK, "secret-key")
	}
	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, "127.0.0.1:9090")
	}
	if cfg.TunnelPath != "/upload" {
		t.Errorf("TunnelPath = %q, want %q", cfg.TunnelPath, "/upload")
	}
	if !cfg.Insecure {
		t.Error("Insecure = false, want true")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	path := writeTestConfig(t, `{
		"server": "example.com:443",
		"psk": "key"
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
	if cfg.Insecure {
		t.Error("Insecure should default to false")
	}
}

func TestLoadConfig_MissingServer(t *testing.T) {
	path := writeTestConfig(t, `{"psk": "key"}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for missing server")
	}
}

func TestLoadConfig_MissingPSK(t *testing.T) {
	path := writeTestConfig(t, `{"server": "example.com:443"}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for missing psk")
	}
}
