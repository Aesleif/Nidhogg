package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/things-go/go-socks5"

	"github.com/aesleif/nidhogg/internal/client"
	"github.com/aesleif/nidhogg/internal/health"
	"github.com/aesleif/nidhogg/internal/logging"
	"github.com/aesleif/nidhogg/internal/shaper"
)

func main() {
	configPath := flag.String("config", "client.json", "path to config file")
	flag.Parse()

	cfg, err := client.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	level, _ := logging.ParseLevel(cfg.LogLevel) // already validated
	logging.Setup(level)

	shapingMode, _ := shaper.ParseMode(cfg.ShapingMode) // already validated in LoadConfig
	dialer := client.NewDialer(cfg.Server, cfg.TunnelPath, []byte(cfg.PSK), cfg.Insecure, cfg.Fingerprint, shapingMode)

	healthCfg := health.Config{
		MaxHandshakeRTT:     time.Duration(cfg.MaxRTTMs) * time.Millisecond,
		MaxWriteLatency:     5 * time.Second,
		ConsecutiveFailures: cfg.ConsecutiveFailures,
		ReadTimeoutLimit:    3,
	}

	srv := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stderr, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			slog.Debug("SOCKS5 CONNECT", "addr", addr)
			conn, prof, rtt, err := dialer.DialTunnel(ctx, addr)
			if err != nil {
				slog.Error("tunnel dial failed", "addr", addr, "err", err)
				return nil, err
			}
			if prof != nil {
				slog.Debug("tunnel established", "addr", addr, "profile", prof.Name, "rtt", rtt)
			} else {
				slog.Debug("tunnel established", "addr", addr, "profile", "none", "rtt", rtt)
			}
			monitored := health.NewMonitoredConn(conn, rtt, healthCfg, addr)
			return monitored, nil
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
		slog.Info("shutting down")
		ln.Close()
	}()

	slog.Info("SOCKS5 proxy listening", "listen", cfg.Listen, "server", cfg.Server)
	if err := srv.Serve(ln); err != nil && ctx.Err() == nil {
		log.Fatalf("SOCKS5 server error: %v", err)
	}
	slog.Info("stopped")
}
