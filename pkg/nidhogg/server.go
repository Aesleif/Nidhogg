package nidhogg

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/telemetry"
	"github.com/aesleif/nidhogg/internal/transport"
)

// ErrUnknownClient is returned by AuthenticateHandshake when the client
// presents a public key that is not in the server's authorized set.
// Callers (e.g. the Xray-core integration) should fall back to their
// cover-site handler so the probe is indistinguishable from a regular
// non-nidhogg HTTP request.
var ErrUnknownClient = errors.New("nidhogg: unknown client public key")

// ServerConfig configures a nidhogg tunnel server.
type ServerConfig struct {
	// AuthorizedKeys is the set of Ed25519 public keys allowed to open
	// tunnels. At least one key is required.
	AuthorizedKeys []ed25519.PublicKey
	// AuthorizedKeyNames is a parallel slice of operator-facing labels
	// (used only in server-side logs). May be shorter than
	// AuthorizedKeys; missing entries become empty strings.
	AuthorizedKeyNames []string
	// CoverUpstream is the host:port of a real HTTPS site used as the
	// fallback reverse-proxy target (and, when paired with the SNI
	// router in the standalone server binary, the raw-TCP forward
	// target for non-matching SNIs). Required for NewServer.
	CoverUpstream string
	// TunnelPath is the HTTP path for the tunnel endpoint. Default: "/".
	TunnelPath string
	// ProfileTargets are hosts used for traffic profile generation. Default: ["google.com"].
	ProfileTargets []string
	// ProfileInterval is how often profiles are regenerated. Default: 6h.
	ProfileInterval time.Duration
	// ProfileMinSnapshots is the minimum traffic snapshots before regeneration. Default: 20.
	ProfileMinSnapshots int
	// TelemetryCriticalThreshold is the number of critical client reports
	// before triggering profile regeneration. Default: 3.
	TelemetryCriticalThreshold int
}

// TelemetryReport is a health report sent by a nidhogg client.
type TelemetryReport struct {
	Profile    string `json:"profile"`
	Status     string `json:"status"`
	AvgRTTMs   int64  `json:"avg_rtt_ms"`
	ErrorCount int    `json:"error_count"`
}

// Server handles incoming nidhogg tunnel connections.
type Server struct {
	auth    *transport.AuthStore
	pm      *server.ProfileManager
	agg     *telemetry.Aggregator
	handler http.Handler
}

func applyServerDefaults(cfg *ServerConfig) error {
	if len(cfg.AuthorizedKeys) == 0 {
		return fmt.Errorf("nidhogg: AuthorizedKeys is required (at least one Ed25519 pubkey)")
	}
	for i, k := range cfg.AuthorizedKeys {
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("nidhogg: AuthorizedKeys[%d] is not a 32-byte Ed25519 pubkey", i)
		}
	}
	if cfg.TunnelPath == "" {
		cfg.TunnelPath = "/"
	}
	if len(cfg.ProfileTargets) == 0 {
		cfg.ProfileTargets = []string{"google.com"}
	}
	if cfg.ProfileInterval == 0 {
		cfg.ProfileInterval = 6 * time.Hour
	}
	if cfg.ProfileMinSnapshots <= 0 {
		cfg.ProfileMinSnapshots = 20
	}
	if cfg.TelemetryCriticalThreshold <= 0 {
		cfg.TelemetryCriticalThreshold = 3
	}
	return nil
}

// NewServerEmbedded creates a server for embedded use (e.g. inside Xray-core)
// where routing is handled externally. No reverse proxy fallback is created.
func NewServerEmbedded(cfg ServerConfig) (*Server, error) {
	if err := applyServerDefaults(&cfg); err != nil {
		return nil, err
	}

	auth := transport.NewAuthStore(cfg.AuthorizedKeys, cfg.AuthorizedKeyNames)
	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileInterval, cfg.ProfileMinSnapshots)
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	return &Server{
		auth: auth,
		pm:   pm,
		agg:  agg,
	}, nil
}

// NewServer creates a tunnel server with the given configuration.
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := applyServerDefaults(&cfg); err != nil {
		return nil, err
	}
	if cfg.CoverUpstream == "" {
		return nil, fmt.Errorf("nidhogg: cover_upstream is required")
	}

	auth := transport.NewAuthStore(cfg.AuthorizedKeys, cfg.AuthorizedKeyNames)
	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileInterval, cfg.ProfileMinSnapshots)
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	proxy, err := server.NewReverseProxy(cfg.CoverUpstream)
	if err != nil {
		return nil, fmt.Errorf("nidhogg: %w", err)
	}

	handler := server.TunnelHandler(auth, server.DefaultDestACL{}, proxy, pm, agg)

	return &Server{
		auth:    auth,
		pm:      pm,
		agg:     agg,
		handler: handler,
	}, nil
}

// Handler returns the http.Handler for the tunnel endpoint.
// It includes the reverse proxy fallback for non-tunnel requests.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// StartProfileManager runs background traffic collection and profile
// generation. Blocks until ctx is cancelled.
func (s *Server) StartProfileManager(ctx context.Context) {
	s.pm.Start(ctx)
}

// AuthenticateHandshake runs the full Ed25519 challenge-response on a
// bidirectional HTTP stream:
//
//  1. Reads the client hello ([version:1][pubkey:32]) from r.
//  2. Looks up the pubkey. On miss, returns ErrUnknownClient — the
//     caller should fall back to its cover-site handler to keep the
//     response indistinguishable from a non-nidhogg request.
//  3. Generates a random 32-byte challenge, writes it to w, flushes.
//  4. Reads the client's 64-byte Ed25519 signature and verifies it
//     against the claimed pubkey.
//
// On success returns the authenticated client public key. On failure
// other than ErrUnknownClient, the server has already committed to
// writing bytes to w and the caller should close the connection rather
// than attempt a fallback.
func (s *Server) AuthenticateHandshake(w io.Writer, r io.Reader, flusher http.Flusher) (ed25519.PublicKey, error) {
	helloBuf := make([]byte, transport.HelloSize)
	if _, err := io.ReadFull(r, helloBuf); err != nil {
		return nil, fmt.Errorf("read hello: %w", err)
	}
	pub, err := transport.ParseHello(helloBuf)
	if err != nil {
		return nil, ErrUnknownClient
	}
	if !s.auth.Has(pub) {
		return nil, ErrUnknownClient
	}

	nonce, err := transport.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	if _, err := w.Write(nonce[:]); err != nil {
		return nil, fmt.Errorf("write nonce: %w", err)
	}
	if flusher != nil {
		flusher.Flush()
	}

	sig := make([]byte, transport.SignatureSize)
	if _, err := io.ReadFull(r, sig); err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if !transport.VerifyChallenge(pub, nonce, sig) {
		return nil, fmt.Errorf("invalid signature")
	}
	return pub, nil
}

// AuthorizedKeyName returns the operator-assigned label for pub, or ""
// if the key is not authorized. Useful for log lines in integrations
// (e.g. the Xray-core fork).
func (s *Server) AuthorizedKeyName(pub ed25519.PublicKey) string {
	return s.auth.Name(pub)
}

// CurrentProfileJSON returns the current traffic profile as JSON bytes and its version hash.
// Returns (nil, 0) if no profile is available.
func (s *Server) CurrentProfileJSON() ([]byte, uint32) {
	prof := s.pm.Current()
	if prof == nil {
		return nil, 0
	}
	data, err := json.Marshal(prof)
	if err != nil {
		return nil, 0
	}
	return data, profile.VersionHash(data)
}

// RecordTelemetry records a health report from a client.
func (s *Server) RecordTelemetry(report TelemetryReport) {
	if s.agg != nil {
		s.agg.Record(telemetry.Report{
			Profile:    report.Profile,
			Status:     report.Status,
			AvgRTTMs:   report.AvgRTTMs,
			ErrorCount: report.ErrorCount,
		})
	}
}

// ShapeRelay returns a (reader, writer) pair wrapped in traffic shaping
// when the server has an active profile and the client signaled that it
// will frame its traffic. Otherwise (r, w) are returned unchanged.
//
// External integrators (e.g. Xray-core) call this after sending the
// inline profile but before starting the relay loop. The returned reader
// unframes incoming bytes from the client, and the writer frames outgoing
// bytes to the client, both using sizes drawn from the profile's CDF.
//
// The server side always uses stream-mode shaping (size padding only,
// no artificial timing delays).
func (s *Server) ShapeRelay(r io.Reader, w io.Writer, clientShaping bool) (io.Reader, io.Writer) {
	if !clientShaping || s.pm == nil {
		return r, w
	}
	prof := s.pm.Current()
	if prof == nil {
		return r, w
	}
	conn := &rwConn{r: r, w: w}
	shaped := shaper.NewShapedConn(conn, prof, shaper.Stream)
	return shaped, shaped
}

// rwConn adapts an io.Reader / io.Writer pair to net.Conn so that
// ShapedConn (which wraps a net.Conn) can drive the underlying transport.
// All address and deadline methods are no-ops — the surrounding HTTP/2
// transport handles those.
type rwConn struct {
	r io.Reader
	w io.Writer
}

func (c *rwConn) Read(b []byte) (int, error)       { return c.r.Read(b) }
func (c *rwConn) Write(b []byte) (int, error)      { return c.w.Write(b) }
func (c *rwConn) Close() error                     { return nil }
func (c *rwConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *rwConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *rwConn) SetDeadline(time.Time) error      { return nil }
func (c *rwConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rwConn) SetWriteDeadline(time.Time) error { return nil }

// Close releases resources held by the server.
func (s *Server) Close() error {
	return nil
}
