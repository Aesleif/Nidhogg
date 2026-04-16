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

	if mc.Level() != health.Healthy {
		t.Fatal("expected Healthy before errors")
	}

	// First 2 writes succeed
	mc.Write([]byte("ok"))
	mc.Write([]byte("ok"))
	if mc.Level() != health.Healthy {
		t.Fatal("expected Healthy after successful writes")
	}

	// 1 write error → Degraded
	mc.Write([]byte("fail"))
	if mc.Level() != health.Degraded {
		t.Errorf("Level = %v, want Degraded after 1 error", mc.Level())
	}

	// 2 more errors → Critical (3 total consecutive)
	mc.Write([]byte("fail"))
	mc.Write([]byte("fail"))
	if mc.Level() != health.Critical {
		t.Errorf("Level = %v, want Critical after 3 errors", mc.Level())
	}

	if mc.IsHealthy() {
		t.Error("expected unhealthy at Critical level")
	}
}

func TestMonitoredConnDegradationCallback(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	inner := &errorConn{Conn: a, failAfter: 0}
	cfg := health.DefaultConfig()
	cfg.ConsecutiveFailures = 3

	var callbackLevels []health.DegradationLevel
	done := make(chan struct{}, 5)

	mc := health.NewMonitoredConn(inner, 10*time.Millisecond, cfg, "test:443")
	mc.OnDegradation = func(level health.DegradationLevel, _ health.ConnStats) {
		callbackLevels = append(callbackLevels, level)
		done <- struct{}{}
	}

	// First write fails → should transition to Degraded
	mc.Write([]byte("fail"))

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("callback not called")
	}

	if len(callbackLevels) == 0 {
		t.Fatal("no callback received")
	}
	if callbackLevels[0] != health.Degraded {
		t.Errorf("first callback level = %v, want Degraded", callbackLevels[0])
	}
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

type timeoutConn struct {
	net.Conn
}

func (c *timeoutConn) Read(b []byte) (int, error) {
	return 0, &timeoutError{}
}

type resetConn struct {
	net.Conn
}

func (c *resetConn) Read(b []byte) (int, error) {
	return 0, errors.New("connection reset by peer")
}

func TestMonitoredConnReadTimeoutCounted(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	inner := &timeoutConn{Conn: a}
	cfg := health.DefaultConfig()
	mc := health.NewMonitoredConn(inner, 10*time.Millisecond, cfg, "test:443")

	mc.Read(make([]byte, 64))
	mc.Read(make([]byte, 64))

	stats := mc.Stats()
	if stats.ReadTimeouts != 2 {
		t.Errorf("ReadTimeouts = %d, want 2", stats.ReadTimeouts)
	}
}

func TestMonitoredConnResetNotCounted(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	inner := &resetConn{Conn: a}
	cfg := health.DefaultConfig()
	mc := health.NewMonitoredConn(inner, 10*time.Millisecond, cfg, "test:443")

	mc.Read(make([]byte, 64))

	stats := mc.Stats()
	if stats.ReadTimeouts != 0 {
		t.Errorf("ReadTimeouts = %d, want 0 (connection reset is not a timeout)", stats.ReadTimeouts)
	}
	if !mc.IsHealthy() {
		t.Error("expected healthy after connection reset")
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
	if stats.Level != health.Critical {
		t.Errorf("Stats.Level = %v, want Critical", stats.Level)
	}
}
