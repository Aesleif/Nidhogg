// Package nidhogg provides a public API for creating nidhogg tunnel
// clients and servers. It wraps the internal implementation packages
// and exposes only the types needed by external consumers (e.g. Xray-core).
package nidhogg

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/transport"
)

// ShapingMode controls how aggressively traffic is shaped.
type ShapingMode int

const (
	// ShapingDisabled means no shaping is applied.
	ShapingDisabled ShapingMode = iota - 1
	// ShapingStream pads packet sizes only, no timing delays.
	ShapingStream
	// ShapingBalanced pads sizes and groups writes into bursts.
	ShapingBalanced
	// ShapingStealth pads sizes, applies timing delays, and groups into bursts.
	ShapingStealth
)

// ParseShapingMode converts a config string to a ShapingMode.
// Accepted values: "" (disabled), "stream", "balanced", "stealth".
func ParseShapingMode(s string) (ShapingMode, error) {
	switch s {
	case "":
		return ShapingDisabled, nil
	case "stream":
		return ShapingStream, nil
	case "balanced":
		return ShapingBalanced, nil
	case "stealth":
		return ShapingStealth, nil
	default:
		return ShapingDisabled, fmt.Errorf("unknown shaping mode: %q", s)
	}
}

// ProfileInfo contains public metadata about a traffic profile.
// Internal CDF/burst data used for shaping is not exposed.
type ProfileInfo struct {
	Name      string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// TunnelConn is a tunnel connection with associated metadata.
type TunnelConn interface {
	net.Conn
	// Profile returns public information about the active traffic profile.
	Profile() ProfileInfo
	// HandshakeRTT returns the time taken for the PSK handshake.
	HandshakeRTT() time.Duration
}

// Command identifies the type of tunnel request.
type Command = transport.Command

const (
	CommandTCP       = transport.CommandTCP
	CommandUDP       = transport.CommandUDP
	CommandTelemetry = transport.CommandTelemetry
)

// Destination represents a parsed tunnel destination.
type Destination = transport.Destination

// WriteDest encodes a Destination in binary format.
func WriteDest(w io.Writer, d Destination) error { return transport.WriteDest(w, d) }

// ReadDest reads a binary-encoded Destination from r.
func ReadDest(r io.Reader) (Destination, error) { return transport.ReadDest(r) }

// toInternalMode converts the public ShapingMode to the internal shaper.ShapingMode.
func toInternalMode(m ShapingMode) shaper.ShapingMode {
	switch m {
	case ShapingStream:
		return shaper.Stream
	case ShapingBalanced:
		return shaper.Balanced
	case ShapingStealth:
		return shaper.Stealth
	default:
		return shaper.Disabled
	}
}

// toProfileInfo converts an internal profile to public ProfileInfo.
func toProfileInfo(p *profile.Profile) ProfileInfo {
	if p == nil {
		return ProfileInfo{}
	}
	return ProfileInfo{
		Name:      p.Name,
		CreatedAt: p.CreatedAt,
		ExpiresAt: p.ExpiresAt,
	}
}

// tunnelConn wraps a net.Conn with profile metadata.
type tunnelConn struct {
	net.Conn
	profile      ProfileInfo
	handshakeRTT time.Duration
}

func (c *tunnelConn) Profile() ProfileInfo        { return c.profile }
func (c *tunnelConn) HandshakeRTT() time.Duration { return c.handshakeRTT }
