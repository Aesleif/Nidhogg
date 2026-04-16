package health_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/health"
)

func TestMonitoredConnHealthy(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	mc := health.NewMonitoredConn(a, 50*time.Millisecond, health.DefaultConfig(), "test:443")

	go func() {
		buf := make([]byte, 64)
		for {
			n, err := b.Read(buf)
			if err != nil {
				return
			}
			b.Write(buf[:n])
		}
	}()

	msg := []byte("hello")
	if _, err := mc.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := mc.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if !mc.IsHealthy() {
		t.Error("expected healthy connection")
	}

	stats := mc.Stats()
	if stats.TotalWritten != int64(len(msg)) {
		t.Errorf("TotalWritten = %d, want %d", stats.TotalWritten, len(msg))
	}
	if stats.TotalRead != int64(len(msg)) {
		t.Errorf("TotalRead = %d, want %d", stats.TotalRead, len(msg))
	}
	if stats.WriteErrors != 0 {
		t.Errorf("WriteErrors = %d, want 0", stats.WriteErrors)
	}
	if stats.HandshakeRTT != 50*time.Millisecond {
		t.Errorf("HandshakeRTT = %v, want 50ms", stats.HandshakeRTT)
	}
}

type errorConn struct {
	net.Conn
	writeCount int
	failAfter  int
}

func (c *errorConn) Write(b []byte) (int, error) {
	c.writeCount++
	if c.writeCount > c.failAfter {
		return 0, errors.New("write failed")
	}
	return len(b), nil
}

func (c *errorConn) Read(b []byte) (int, error) {
	return 0, errors.New("read failed")
}

func TestMonitoredConnWriteErrors(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	inner := &errorConn{Conn: a, failAfter: 2}
	cfg := health.DefaultConfig()
	cfg.ConsecutiveFailures = 3
	mc := health.NewMonitoredConn(inner, 10*time.Millisecond, cfg, "test:443")

	if !mc.IsHealthy() {
		t.Fatal("expected healthy before errors")
	}

	// First 2 writes succeed
	mc.Write([]byte("ok"))
	mc.Write([]byte("ok"))
	if !mc.IsHealthy() {
		t.Fatal("expected healthy after successful writes")
	}

	// Next 3 writes fail — should become unhealthy
	mc.Write([]byte("fail"))
	mc.Write([]byte("fail"))
	mc.Write([]byte("fail"))

	if mc.IsHealthy() {
		t.Error("expected unhealthy after consecutive write errors")
	}

	stats := mc.Stats()
	if stats.WriteErrors < 3 {
		t.Errorf("WriteErrors = %d, want >= 3", stats.WriteErrors)
	}
}

func TestMonitoredConnHighRTT(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	cfg := health.DefaultConfig()
	cfg.MaxHandshakeRTT = 100 * time.Millisecond
	mc := health.NewMonitoredConn(a, 500*time.Millisecond, cfg, "test:443")

	if mc.IsHealthy() {
		t.Error("expected unhealthy with high handshake RTT")
	}

	stats := mc.Stats()
	if stats.Healthy {
		t.Error("Stats.Healthy should be false")
	}
}
