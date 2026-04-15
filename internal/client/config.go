package client

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/transport"
)

type Config struct {
	Server      string `json:"server"`
	PSK         string `json:"psk"`
	Listen      string `json:"listen"`
	TunnelPath  string `json:"tunnel_path"`
	Insecure    bool   `json:"insecure"`
	Fingerprint string `json:"fingerprint"`  // "randomized" (default), "chrome", "firefox", "safari"
	ShapingMode string `json:"shaping_mode"` // "", "stream", "balanced", "stealth"
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Server == "" {
		return nil, fmt.Errorf("server is required")
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("psk is required")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:1080"
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/"
	}

	if _, err := transport.FingerprintID(cfg.Fingerprint); err != nil {
		return nil, fmt.Errorf("invalid fingerprint: %w", err)
	}
	if _, err := shaper.ParseMode(cfg.ShapingMode); err != nil {
		return nil, fmt.Errorf("invalid shaping_mode: %w", err)
	}

	return &cfg, nil
}
