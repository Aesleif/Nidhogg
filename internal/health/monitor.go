package health

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const writeSampleSize = 10

type Config struct {
	MaxHandshakeRTT     time.Duration
	MaxWriteLatency     time.Duration
	ConsecutiveFailures int
	ReadTimeoutLimit    int
}

func DefaultConfig() Config {
	return Config{
		MaxHandshakeRTT:     2 * time.Second,
		MaxWriteLatency:     5 * time.Second,
		ConsecutiveFailures: 3,
		ReadTimeoutLimit:    3,
	}
}

type ConnStats struct {
	HandshakeRTT    time.Duration
	WriteErrors     int
	ReadTimeouts    int
	TotalRead       int64
	TotalWritten    int64
	Duration        time.Duration
	AvgWriteLatency time.Duration
	Healthy         bool
}

type MonitoredConn struct {
	net.Conn
	cfg          Config
	handshakeRTT time.Duration
	startedAt    time.Time
	dest         string

	mu           sync.Mutex
	writeErrors  int
	readTimeouts int
	lastReadAt   time.Time
	writeSamples [writeSampleSize]time.Duration
	writeIdx     int
	writeCount   int

	totalRead    atomic.Int64
	totalWritten atomic.Int64
}

func NewMonitoredConn(conn net.Conn, handshakeRTT time.Duration, cfg Config, dest string) *MonitoredConn {
	now := time.Now()
	return &MonitoredConn{
		Conn:         conn,
		cfg:          cfg,
		handshakeRTT: handshakeRTT,
		startedAt:    now,
		lastReadAt:   now,
		dest:         dest,
	}
}

func (c *MonitoredConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.totalRead.Add(int64(n))
		c.mu.Lock()
		c.lastReadAt = time.Now()
		c.mu.Unlock()
	}
	if err != nil && err != io.EOF {
		c.mu.Lock()
		c.readTimeouts++
		c.mu.Unlock()
	}
	return n, err
}

func (c *MonitoredConn) Write(b []byte) (int, error) {
	start := time.Now()
	n, err := c.Conn.Write(b)
	latency := time.Since(start)

	if n > 0 {
		c.totalWritten.Add(int64(n))
	}

	c.mu.Lock()
	if err != nil {
		c.writeErrors++
	} else {
		c.writeErrors = 0
		c.writeSamples[c.writeIdx] = latency
		c.writeIdx = (c.writeIdx + 1) % writeSampleSize
		if c.writeCount < writeSampleSize {
			c.writeCount++
		}
	}
	c.mu.Unlock()

	return n, err
}

func (c *MonitoredConn) Close() error {
	stats := c.Stats()
	slog.Debug("tunnel closed",
		"dest", c.dest,
		"rtt", stats.HandshakeRTT,
		"duration", stats.Duration,
		"read", stats.TotalRead,
		"written", stats.TotalWritten,
		"healthy", stats.Healthy,
		"write_errors", stats.WriteErrors,
		"read_timeouts", stats.ReadTimeouts,
		"avg_write_latency", stats.AvgWriteLatency,
	)
	return c.Conn.Close()
}

func (c *MonitoredConn) IsHealthy() bool {
	if c.handshakeRTT > c.cfg.MaxHandshakeRTT {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writeErrors >= c.cfg.ConsecutiveFailures {
		return false
	}
	if c.readTimeouts >= c.cfg.ReadTimeoutLimit {
		return false
	}
	if c.writeCount > 0 && c.avgWriteLatency() > c.cfg.MaxWriteLatency {
		return false
	}
	return true
}

func (c *MonitoredConn) Stats() ConnStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	return ConnStats{
		HandshakeRTT:    c.handshakeRTT,
		WriteErrors:     c.writeErrors,
		ReadTimeouts:    c.readTimeouts,
		TotalRead:       c.totalRead.Load(),
		TotalWritten:    c.totalWritten.Load(),
		Duration:        time.Since(c.startedAt),
		AvgWriteLatency: c.avgWriteLatency(),
		Healthy:         c.isHealthyLocked(),
	}
}

// must be called under c.mu
func (c *MonitoredConn) avgWriteLatency() time.Duration {
	if c.writeCount == 0 {
		return 0
	}
	var total time.Duration
	for i := 0; i < c.writeCount; i++ {
		total += c.writeSamples[i]
	}
	return total / time.Duration(c.writeCount)
}

// must be called under c.mu
func (c *MonitoredConn) isHealthyLocked() bool {
	if c.handshakeRTT > c.cfg.MaxHandshakeRTT {
		return false
	}
	if c.writeErrors >= c.cfg.ConsecutiveFailures {
		return false
	}
	if c.readTimeouts >= c.cfg.ReadTimeoutLimit {
		return false
	}
	if c.writeCount > 0 && c.avgWriteLatency() > c.cfg.MaxWriteLatency {
		return false
	}
	return true
}
