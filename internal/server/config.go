package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aesleif/nidhogg/internal/logging"
)

type Config struct {
	Listen string `json:"listen"`
	Domain string `json:"domain"`
	// AuthorizedKeys is the list of Ed25519 public keys authorized to
	// open tunnels. Each entry is base64(32-byte pubkey), optionally
	// followed by a space and a human-readable label used only in
	// server-side logging:
	//   "<b64-pubkey>"
	//   "<b64-pubkey> alice-laptop"
	AuthorizedKeys             []string `json:"authorized_keys"`
	CoverUpstream              string   `json:"cover_upstream"` // host:port; doubles as raw-TCP forward target for non-matching SNI and HTTP fallback for unknown clients
	TunnelPath                 string   `json:"tunnel_path"`
	CertFile                   string   `json:"cert_file,omitempty"`
	KeyFile                    string   `json:"key_file,omitempty"`
	ProfileTargets             []string `json:"profile_targets"`
	ProfileInterval            string   `json:"profile_interval"`
	ProfileMinSnapshots        int      `json:"profile_min_snapshots"`
	TelemetryCriticalThreshold int      `json:"telemetry_critical_threshold"`
	LogLevel                   string   `json:"log_level"`
}

// ParsedAuthorizedKeys decodes AuthorizedKeys into (keys, names) slices.
// Invalid entries are reported as errors; callers decide whether to
// abort or warn. Names are parallel to keys ("" when no label given).
func (c *Config) ParsedAuthorizedKeys() ([]ed25519.PublicKey, []string, error) {
	keys := make([]ed25519.PublicKey, 0, len(c.AuthorizedKeys))
	names := make([]string, 0, len(c.AuthorizedKeys))
	for i, line := range c.AuthorizedKeys {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var encoded, name string
		if idx := strings.IndexAny(line, " \t"); idx >= 0 {
			encoded = line[:idx]
			name = strings.TrimSpace(line[idx+1:])
		} else {
			encoded = line
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("authorized_keys[%d]: base64 decode: %w", i, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("authorized_keys[%d]: want %d bytes, got %d", i, ed25519.PublicKeySize, len(raw))
		}
		keys = append(keys, ed25519.PublicKey(raw))
		names = append(names, name)
	}
	return keys, names, nil
}

// ProfileIntervalDuration parses ProfileInterval as a time.Duration.
// Returns 6h if not set.
func (c *Config) ProfileIntervalDuration() time.Duration {
	if c.ProfileInterval == "" {
		return 6 * time.Hour
	}
	d, err := time.ParseDuration(c.ProfileInterval)
	if err != nil {
		return 6 * time.Hour
	}
	return d
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
	if len(cfg.AuthorizedKeys) == 0 {
		return nil, fmt.Errorf("authorized_keys is required (at least one base64 Ed25519 pubkey)")
	}
	if _, _, err := cfg.ParsedAuthorizedKeys(); err != nil {
		return nil, err
	}
	if cfg.CoverUpstream == "" {
		return nil, fmt.Errorf("cover_upstream is required (host:port of a real HTTPS site to mimic)")
	}
	if cfg.Domain == "" && cfg.CertFile == "" {
		return nil, fmt.Errorf("domain is required when cert_file is not set (needed for Let's Encrypt)")
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return nil, fmt.Errorf("cert_file and key_file must both be set or both be empty")
	}
	if len(cfg.ProfileTargets) == 0 {
		cfg.ProfileTargets = []string{"google.com"}
	}
	if cfg.ProfileMinSnapshots <= 0 {
		cfg.ProfileMinSnapshots = 20
	}
	if cfg.TelemetryCriticalThreshold <= 0 {
		cfg.TelemetryCriticalThreshold = 3
	}
	if _, err := logging.ParseLevel(cfg.LogLevel); err != nil {
		return nil, fmt.Errorf("invalid log_level: %w", err)
	}

	return &cfg, nil
}
