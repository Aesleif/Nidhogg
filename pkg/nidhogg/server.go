package nidhogg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/telemetry"
	"github.com/aesleif/nidhogg/internal/transport"
)

// ServerConfig configures a nidhogg tunnel server.
type ServerConfig struct {
	// PSK is the pre-shared key for tunnel authentication. Required.
	PSK string
	// ProxyTo is the reverse proxy fallback URL for non-tunnel requests. Required.
	ProxyTo string
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
	if cfg.ProxyTo == "" {
		return nil, fmt.Errorf("nidhogg: proxy_to is required")
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

	proxy, err := server.NewReverseProxy(cfg.ProxyTo)
	if err != nil {
		return nil, fmt.Errorf("nidhogg: %w", err)
	}

	handler := server.TunnelHandler(psk, proxy, pm, agg)

	return &Server{
		psk:       psk,
		validator: transport.NewValidator(psk),
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
// generation. It blocks until ctx is cancelled.
func (s *Server) StartProfileManager(ctx context.Context) {
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

// CurrentProfileJSON returns the current traffic profile as JSON bytes.
// Returns nil if no profile is available.
func (s *Server) CurrentProfileJSON() []byte {
	prof := s.pm.Current()
	if prof == nil {
		return nil
	}
	data, err := json.Marshal(prof)
	if err != nil {
		return nil
	}
	return data
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

// Close releases resources held by the server.
func (s *Server) Close() error {
	return nil
}
