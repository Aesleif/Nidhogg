package nidhogg

import (
	"context"
	"encoding/json"
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

// ServerConfig configures a nidhogg tunnel server.
type ServerConfig struct {
	// PSK is the pre-shared key for tunnel authentication. Required.
	PSK string
	// CoverUpstream is the host:port of a real HTTPS site used as the
	// PSK-fallback HTTP reverse-proxy target (and, when paired with the
	// SNI router in the standalone server binary, the raw-TCP forward
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
	psk       []byte
	validator *transport.HandshakeValidator
	pm        *server.ProfileManager
	agg       *telemetry.Aggregator
	handler   http.Handler
}

// NewServerEmbedded creates a server for embedded use (e.g. inside Xray-core)
// where routing is handled externally. No reverse proxy fallback is created.
func NewServerEmbedded(cfg ServerConfig) (*Server, error) {
	if cfg.PSK == "" {
		return nil, fmt.Errorf("nidhogg: PSK is required")
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

	psk := []byte(cfg.PSK)
	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileInterval, cfg.ProfileMinSnapshots)
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	return &Server{
		psk:       psk,
		validator: transport.NewValidator(psk),
		pm:        pm,
		agg:       agg,
	}, nil
}

// NewServer creates a tunnel server with the given configuration.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.PSK == "" {
		return nil, fmt.Errorf("nidhogg: PSK is required")
	}
	if cfg.CoverUpstream == "" {
		return nil, fmt.Errorf("nidhogg: cover_upstream is required")
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

	psk := []byte(cfg.PSK)

	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileInterval, cfg.ProfileMinSnapshots)
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	proxy, err := server.NewReverseProxy(cfg.CoverUpstream)
	if err != nil {
		return nil, fmt.Errorf("nidhogg: %w", err)
	}

	validator := transport.NewValidator(psk)
	handler := server.TunnelHandler(psk, validator, proxy, pm, agg)

	return &Server{
		psk:       psk,
		validator: validator,
		pm:        pm,
		agg:       agg,
		handler:   handler,
	}, nil
}

// Handler returns the http.Handler for the tunnel endpoint.
// It includes the reverse proxy fallback for non-tunnel requests.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// StartProfileManager runs background traffic collection and profile
// generation. It also starts the handshake validator's nonce cleanup
// loop so stale entries are swept during idle periods. Blocks until
// ctx is cancelled.
func (s *Server) StartProfileManager(ctx context.Context) {
	go s.validator.StartCleanupLoop(ctx, time.Minute)
	s.pm.Start(ctx)
}

// ValidateHandshake validates a PSK handshake from a client.
// Returns true if the handshake is valid.
func (s *Server) ValidateHandshake(data []byte) (bool, error) {
	return s.validator.Validate(data)
}

// HandshakeSize returns the expected PSK handshake size in bytes.
func HandshakeSize() int {
	return transport.HandshakeSize
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
