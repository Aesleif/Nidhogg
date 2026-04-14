package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/aesleif/nidhogg/internal/server"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	proxy, err := server.NewReverseProxy(cfg.ProxyTo)
	if err != nil {
		log.Fatalf("failed to create reverse proxy: %v", err)
	}

	psk := []byte(cfg.PSK)

	// Tunnel handler on tunnel_path, everything else goes to reverse proxy
	mux := http.NewServeMux()
	tunnelHandler := server.TunnelHandler(psk, proxy)
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
			log.Printf("starting ACME HTTP-01 challenge server on :80")
			if err := http.ListenAndServe(":80", h); err != nil {
				log.Printf("ACME HTTP server error: %v", err)
			}
		}()
	}

	// Graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("starting server on %s (domain: %s, tunnel: %s)", cfg.Listen, cfg.Domain, cfg.TunnelPath)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	log.Printf("server stopped")
}
