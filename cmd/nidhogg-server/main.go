package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"

	_ "net/http/pprof"

	"github.com/aesleif/nidhogg/internal/logging"
	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/telemetry"
	"github.com/aesleif/nidhogg/internal/transport"
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

	proxy, err := server.NewReverseProxy(cfg.CoverUpstream)
	if err != nil {
		log.Fatalf("failed to create reverse proxy: %v", err)
	}

	psk := []byte(cfg.PSK)

	validator := transport.NewValidator(psk)

	// Profile manager: generates traffic profiles from target sites
	pm := server.NewProfileManager(cfg.ProfileTargets, cfg.ProfileIntervalDuration(), cfg.ProfileMinSnapshots)

	// Telemetry aggregator
	agg := telemetry.NewAggregator(pm, cfg.TelemetryCriticalThreshold)

	// Tunnel handler on tunnel_path, everything else goes to reverse proxy
	mux := http.NewServeMux()
	tunnelHandler := server.TunnelHandler(psk, validator, proxy, pm, agg)
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

	// Tune HTTP/2 for proxy workload: many concurrent streams, big upload
	// buffers (clients pump TLS records of upstream traffic through us),
	// and bigger DATA frames to amortize per-frame overhead.
	if err := http2.ConfigureServer(srv, &http2.Server{
		MaxConcurrentStreams:         1000,
		MaxUploadBufferPerStream:     8 << 20,
		MaxUploadBufferPerConnection: 64 << 20,
		// 64 KiB frame size: per-stream scratch buffer scales with this
		// on both sides. 1 MiB blew up to ~200MB at ~200 active streams.
		// 64 KiB still gives 4× fewer frames vs the 16 KiB default for
		// bulk transfers, which is the only place frame count matters.
		MaxReadFrameSize: 1 << 16,
		// Keepalive: ping idle connections and close ones whose peer
		// silently went away. Without this, half-dead clients (NAT
		// timeout, RST lost) leak goroutines blocked on io.Copy.
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}); err != nil {
		log.Fatalf("failed to configure HTTP/2: %v", err)
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

	// pprof on loopback for production heap/goroutine profiling.
	// Bound to 127.0.0.1 so no auth needed; ssh-tunnel from the operator
	// box to access (`ssh -L 6060:localhost:6060 server`).
	// Block + mutex profiles are sampled at full rate — small CPU cost in
	// exchange for being able to debug latency/contention regressions
	// without redeploy. Lower the rate (e.g. 1000) if it ever shows up.
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	go func() {
		const addr = "127.0.0.1:6060"
		slog.Info("starting pprof", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			slog.Error("pprof server error", "err", err)
		}
	}()

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go pm.Start(ctx)
	// Sweep expired nonces every minute so idle periods don't retain
	// stale entries up to the 10 000-nonce cap until the next handshake.
	go validator.StartCleanupLoop(ctx, time.Minute)

	// SNI-router loop: peek every accepted TLS ClientHello and dispatch.
	// SNI matching cfg.Domain → terminate TLS locally and serve nidhogg.
	// Anything else → raw-TCP forward to cfg.CoverUpstream so probers
	// see that real site's cert and TLS handshake byte-for-byte.
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.Listen, err)
	}
	router := &server.SNIRouter{
		OurDomain:     cfg.Domain,
		CoverUpstream: cfg.CoverUpstream,
		NidhoggHandler: func(c net.Conn) {
			// Hand the (already-peeked) conn to http.Server through a
			// one-shot listener. http.Server completes TLS via tlsCfg.
			tlsConn := tls.Server(c, tlsCfg)
			singleLn := server.NewSingleConnListener(tlsConn)
			_ = srv.Serve(singleLn)
		},
	}
	go func() {
		slog.Info("starting server", "listen", cfg.Listen, "domain", cfg.Domain, "tunnel", cfg.TunnelPath, "cover_upstream", cfg.CoverUpstream)
		if err := router.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Fatalf("router error: %v", err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = ln.Close() // stop accepting new conns
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	slog.Info("server stopped")
}
