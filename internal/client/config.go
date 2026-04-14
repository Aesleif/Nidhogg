package client

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Server     string `json:"server"`
	PSK        string `json:"psk"`
	Listen     string `json:"listen"`
	TunnelPath string `json:"tunnel_path"`
	Insecure   bool   `json:"insecure"`
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

	return &cfg, nil
}
