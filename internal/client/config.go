package client

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/aesleif/nidhogg/internal/logging"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/transport"
)

type Config struct {
	Server              string `json:"server"`
	PrivateKey          string `json:"private_key"` // base64-encoded Ed25519 private key (64 bytes: seed||pubkey)
	Listen              string `json:"listen"`
	TunnelPath          string `json:"tunnel_path"`
	Fingerprint         string `json:"fingerprint"`          // "randomized" (default), "chrome", "firefox", "safari"
	ShapingMode         string `json:"shaping_mode"`         // "", "stream", "balanced", "stealth"
	LogLevel            string `json:"log_level"`            // "debug", "info" (default), "warn", "error"
	MaxRTTMs            int    `json:"max_rtt_ms"`           // max handshake RTT in ms, default 2000
	ConsecutiveFailures int    `json:"consecutive_failures"` // write errors before unhealthy, default 3
	TelemetryInterval   string `json:"telemetry_interval"`   // e.g. "30s", default "30s"
	ConnectionPoolSize  int    `json:"connection_pool_size"` // parallel TCP+TLS connections, default 4
	IdleTimeout         string `json:"idle_timeout"`         // close tunnel after no activity, e.g. "5m", default "5m"
	ConnectionMaxAge    string `json:"connection_max_age"`   // recycle pooled HTTP/2 conns after this age, e.g. "1h", default "1h"
}

// PrivateKeyBytes decodes the base64 PrivateKey field into an Ed25519
// private key. Used by the client main to hand the key to the Dialer.
func (c *Config) PrivateKeyBytes() (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("private_key: base64 decode: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private_key: want %d bytes, got %d", ed25519.PrivateKeySize, len(raw))
	}
	return ed25519.PrivateKey(raw), nil
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
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("private_key is required")
	}
	if _, err := cfg.PrivateKeyBytes(); err != nil {
		return nil, err
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
	if _, err := logging.ParseLevel(cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("invalid log_level: %w", err)
	}
	if cfg.MaxRTTMs <= 0 {
		cfg.MaxRTTMs = 2000
	}
	if cfg.ConsecutiveFailures <= 0 {
		cfg.ConsecutiveFailures = 3
	}
	if cfg.TelemetryInterval == "" {
		cfg.TelemetryInterval = "30s"
	}
	if cfg.ConnectionPoolSize <= 0 {
		cfg.ConnectionPoolSize = 4
	}
	if cfg.IdleTimeout == "" {
		cfg.IdleTimeout = "5m"
	}
	if _, err := time.ParseDuration(cfg.IdleTimeout); err != nil {
		return nil, fmt.Errorf("invalid idle_timeout: %w", err)
	}
	if cfg.ConnectionMaxAge == "" {
		cfg.ConnectionMaxAge = "1h"
	}
	if _, err := time.ParseDuration(cfg.ConnectionMaxAge); err != nil {
		return nil, fmt.Errorf("invalid connection_max_age: %w", err)
	}

	return &cfg, nil
}

func (c *Config) TelemetryIntervalDuration() time.Duration {
	d, err := time.ParseDuration(c.TelemetryInterval)
	if err != nil || d <= 0 {
		return 30 * time.Second
	}
	return d
}

func (c *Config) IdleTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(c.IdleTimeout)
	if err != nil || d <= 0 {
		return 5 * time.Minute
	}
	return d
}

func (c *Config) ConnectionMaxAgeDuration() time.Duration {
	d, err := time.ParseDuration(c.ConnectionMaxAge)
	if err != nil || d <= 0 {
		return time.Hour
	}
	return d
}
