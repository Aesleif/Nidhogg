package nidhogg

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/aesleif/nidhogg/internal/client"
)

// ClientConfig configures a nidhogg tunnel client.
type ClientConfig struct {
	// Server is the nidhogg server address in "host:port" format. Required.
	Server string
	// PrivateKey is the client's Ed25519 private key (64 bytes:
	// seed || pubkey, as produced by ed25519.GenerateKey). Required.
	PrivateKey ed25519.PrivateKey
	// TunnelPath is the HTTP path for the tunnel endpoint. Default: "/".
	TunnelPath string
	// Fingerprint controls the TLS ClientHello: "randomized" (default),
	// "chrome", "firefox", "safari".
	Fingerprint string
	// ShapingMode controls traffic shaping applied to tunnel connections.
	ShapingMode ShapingMode
	// ConnectionPoolSize is the number of parallel TCP+TLS connections
	// the HTTP/2 transport keeps to the server. Default: 4 (when zero).
	// Set to 1 to use a single connection.
	ConnectionPoolSize int
	// IdleTimeout closes a tunnel after that long without Read/Write
	// activity. Bounds the cost of half-dead tunnels stuck on silent
	// peers. Default: 5 minutes (when zero). Set to a negative value
	// to disable (not recommended for long-running clients).
	IdleTimeout time.Duration
	// ConnectionMaxAge retires pooled HTTP/2 connections older than that
	// and gracefully redials replacements. Prevents gradual latency
	// degradation from accumulated h2 internal state and stale TCP paths
	// on long-lived connections. Default: 1 hour (when zero). Negative
	// disables recycling.
	ConnectionMaxAge time.Duration
}

// Client creates tunnel connections to a nidhogg server.
type Client struct {
	dialer *client.Dialer
}

// NewClient creates a tunnel client with the given configuration.
func NewClient(cfg ClientConfig) (*Client, error) {
	return newClient(cfg, nil)
}

// newClient is the shared constructor used by NewClient (production,
// rootCAs=nil → system roots) and by tests which inject a custom pool.
func newClient(cfg ClientConfig, rootCAs *x509.CertPool) (*Client, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("nidhogg: server address is required")
	}
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("nidhogg: PrivateKey is required (%d bytes)", ed25519.PrivateKeySize)
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/"
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "randomized"
	}
	if cfg.ConnectionPoolSize == 0 {
		cfg.ConnectionPoolSize = 4
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.ConnectionMaxAge == 0 {
		cfg.ConnectionMaxAge = time.Hour
	}

	d := client.NewDialer(
		cfg.Server,
		cfg.TunnelPath,
		cfg.PrivateKey,
		rootCAs,
		cfg.Fingerprint,
		toInternalMode(cfg.ShapingMode),
		cfg.ConnectionPoolSize,
		cfg.IdleTimeout,
		cfg.ConnectionMaxAge,
	)
	return &Client{dialer: d}, nil
}

// Dial opens a tunnel to the given destination (host:port) through
// the nidhogg server. The returned TunnelConn is shaped and monitored
// according to the client configuration.
func (c *Client) Dial(ctx context.Context, dest string) (TunnelConn, error) {
	conn, prof, rtt, err := c.dialer.DialTunnel(ctx, dest)
	if err != nil {
		return nil, err
	}
	return &tunnelConn{
		Conn:         conn,
		profile:      toProfileInfo(prof),
		handshakeRTT: rtt,
	}, nil
}

// Close releases resources held by the client.
func (c *Client) Close() error {
	return nil
}
