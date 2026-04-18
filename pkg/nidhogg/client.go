package nidhogg

import (
	"context"
	"fmt"

	"github.com/aesleif/nidhogg/internal/client"
)

// ClientConfig configures a nidhogg tunnel client.
type ClientConfig struct {
	// Server is the nidhogg server address in "host:port" format. Required.
	Server string
	// PSK is the pre-shared key for tunnel authentication. Required.
	PSK string
	// TunnelPath is the HTTP path for the tunnel endpoint. Default: "/".
	TunnelPath string
	// Insecure skips TLS certificate verification.
	Insecure bool
	// Fingerprint controls the TLS ClientHello: "randomized" (default),
	// "chrome", "firefox", "safari".
	Fingerprint string
	// ShapingMode controls traffic shaping applied to tunnel connections.
	ShapingMode ShapingMode
}

// Client creates tunnel connections to a nidhogg server.
type Client struct {
	dialer *client.Dialer
}

// NewClient creates a tunnel client with the given configuration.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("nidhogg: server address is required")
	}
	if cfg.PSK == "" {
		return nil, fmt.Errorf("nidhogg: PSK is required")
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/"
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = "randomized"
	}

	d := client.NewDialer(
		cfg.Server,
		cfg.TunnelPath,
		[]byte(cfg.PSK),
		cfg.Insecure,
		cfg.Fingerprint,
		toInternalMode(cfg.ShapingMode),
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
