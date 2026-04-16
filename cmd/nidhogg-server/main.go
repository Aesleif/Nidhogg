package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/aesleif/nidhogg/internal/logging"
	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/telemetry"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	level, _ := logging.ParseLevel(cfg.LogLevel) // already validated
	logging.Setup(level)

	proxy, err := server.NewReverseProxy(cfg.ProxyTo)
	if err != nil {
		log.Fatalf("failed to create reverse proxy: %v", err)
	}

	psk := []byte(cfg.PSK)

	// Profile manager: generates traffic profiles from target sites
	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileIntervalDuration(), cfg.ProfileMinSnapshots)

	// Telemetry aggregator
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	// Tunnel handler on tunnel_path, everything else goes to reverse proxy
	mux := http.NewServeMux()
	tunnelHandler := server.TunnelHandler(psk, proxy, pm, agg)
	mux.Handle(cfg.TunnelPath, tunnelHandler)
	if cfg.TunnelPath != "/" {
		mux.Handle("/", proxy)
	}

	// TLS configuration
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	srv := &http.Server{
		Addr:      cfg.Listen,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	if cfg.CertFile != "" {
		// Use provided certificate files
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			log.Fatalf("failed to load TLS certificate: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	} else {
		// Use Let's Encrypt via autocert
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache("autocert-cache"),
		}
		tlsCfg.GetCertificate = manager.GetCertificate

		// HTTP-01 challenge handler on port 80
		go func() {
			h := manager.HTTPHandler(nil)
			slog.Info("starting ACME HTTP-01 challenge server", "addr", ":80")
			if err := http.ListenAndServe(":80", h); err != nil {
				slog.Error("ACME HTTP server error", "err", err)
			}
		}()
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go pm.Start(ctx)

	go func() {
		slog.Info("starting server", "listen", cfg.Listen, "domain", cfg.Domain, "tunnel", cfg.TunnelPath)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	slog.Info("server stopped")
}
