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
	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/switcher"
	"github.com/aesleif/nidhogg/internal/telemetry"
	"github.com/aesleif/nidhogg/internal/udprelay"
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
	dialer := client.NewDialer(cfg.Server, cfg.TunnelPath, []byte(cfg.PSK), cfg.Insecure, cfg.Fingerprint, shapingMode, cfg.ConnectionPoolSize)

	healthCfg := health.Config{
		MaxHandshakeRTT:     time.Duration(cfg.MaxRTTMs) * time.Millisecond,
		MaxWriteLatency:     5 * time.Second,
		ConsecutiveFailures: cfg.ConsecutiveFailures,
		ReadTimeoutLimit:    3,
	}

	tracker := health.NewTracker()

	sw := switcher.NewSwitcher(5)
	sw.OnSwitch = func(old, new *profile.Profile) {
		oldName, newName := "<none>", "<none>"
		if old != nil {
			oldName = old.Name
		}
		if new != nil {
			newName = new.Name
		}
		slog.Info("profile switched", "from", oldName, "to", newName)
		if new != nil {
			dialer.ProfileOverride.Store(new)
		}
	}

	srv := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stderr, "socks5: ", log.LstdFlags))),
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest := addr
			if network == "udp" {
				dest = "udp:" + addr
			}
			slog.Debug("SOCKS5 dial", "network", network, "addr", addr)
			conn, prof, rtt, err := dialer.DialTunnel(ctx, dest)
			if err != nil {
				slog.Error("tunnel dial failed", "addr", addr, "err", err)
				return nil, err
			}
			if prof != nil {
				slog.Debug("tunnel established", "addr", addr, "profile", prof.Name, "rtt", rtt)
			} else {
				slog.Debug("tunnel established", "addr", addr, "profile", "none", "rtt", rtt)
			}

			tracker.RecordRTT(rtt)
			if prof != nil {
				tracker.SetProfile(prof)
				sw.Push(prof)
			}

			monitored := health.NewMonitoredConn(conn, rtt, healthCfg, addr)
			monitored.OnDegradation = func(level health.DegradationLevel, stats health.ConnStats) {
				slog.Warn("tunnel health changed",
					"dest", addr, "level", level,
					"write_errors", stats.WriteErrors,
					"read_timeouts", stats.ReadTimeouts,
					"avg_write_latency", stats.AvgWriteLatency)

				if tracker.AggregateLevel() == health.Critical {
					slog.Warn("aggregate health critical, switching profile")
					sw.Switch()
				}
			}
			tracker.TrackConn(monitored)
			monitored.OnClose = func() {
				tracker.UntrackConn(monitored)
			}
			if network == "udp" {
				return udprelay.NewPacketFrameConn(monitored), nil
			}
			return monitored, nil
		}),
	)
	sender := telemetry.NewSender(
		dialer.ServerURL(), []byte(cfg.PSK), dialer.Client(),
		cfg.TelemetryIntervalDuration(), tracker, sw,
	)
	sender.OnProfile = func(p *profile.Profile) {
		sw.Push(p)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go sender.Start(ctx)

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
