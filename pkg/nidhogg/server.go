package nidhogg

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/telemetry"
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

// Server handles incoming nidhogg tunnel connections.
type Server struct {
	psk     []byte
	pm      *server.ProfileManager
	agg     *telemetry.Aggregator
	handler http.Handler
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
		psk:     psk,
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
// generation. It blocks until ctx is cancelled.
func (s *Server) StartProfileManager(ctx context.Context) {
	s.pm.Start(ctx)
}

// Close releases resources held by the server.
func (s *Server) Close() error {
	return nil
}
