package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/things-go/go-socks5"

	"github.com/aesleif/nidhogg/internal/client"
)

func main() {
	configPath := flag.String("config", "client.json", "path to config file")
	flag.Parse()

	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	dialer := client.NewDialer(cfg.Server, cfg.TunnelPath, []byte(cfg.PSK), cfg.Insecure, cfg.Fingerprint)

	srv := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stderr, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("SOCKS5 CONNECT → %s", addr)
			conn, err := dialer.DialTunnel(ctx, addr)
			if err != nil {
				log.Printf("tunnel dial failed for %s: %v", addr, err)
				return nil, err
			}
			log.Printf("tunnel established → %s", addr)
			return conn, nil
		}),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", cfg.Listen, err)
	}

	go func() {
		<-ctx.Done()
		log.Printf("shutting down...")
		ln.Close()
	}()

	log.Printf("SOCKS5 proxy listening on %s (server: %s)", cfg.Listen, cfg.Server)
	if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
		log.Fatalf("SOCKS5 server error: %v", err)
	}
	log.Printf("stopped")
}
