package server

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Listen     string `json:"listen"`
	Domain     string `json:"domain"`
	PSK        string `json:"psk"`
	ProxyTo    string `json:"proxy_to"`
	TunnelPath string `json:"tunnel_path"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
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

	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/"
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("psk is required")
	}
	if cfg.ProxyTo == "" {
		return nil, fmt.Errorf("proxy_to is required")
	}
	if cfg.Domain == "" && cfg.CertFile == "" {
		return nil, fmt.Errorf("domain is required when cert_file is not set (needed for Let's Encrypt)")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("cert_file and key_file must both be set or both be empty")
	}

	return &cfg, nil
}
