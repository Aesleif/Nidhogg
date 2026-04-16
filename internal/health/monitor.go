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
	Level           DegradationLevel
}

type MonitoredConn struct {
	net.Conn
	cfg          Config
	handshakeRTT time.Duration
	startedAt    time.Time
	dest         string

	OnDegradation func(DegradationLevel, ConnStats)
	OnClose       func()

	mu           sync.Mutex
	writeErrors  int
	readTimeouts int
	lastReadAt   time.Time
	writeSamples [writeSampleSize]time.Duration
	writeIdx     int
	writeCount   int
	level        DegradationLevel

	totalRead    atomic.Int64
	totalWritten atomic.Int64
}

func NewMonitoredConn(conn net.Conn, handshakeRTT time.Duration, cfg Config, dest string) *MonitoredConn {
	now := time.Now()
	mc := &MonitoredConn{
		Conn:         conn,
		cfg:          cfg,
		handshakeRTT: handshakeRTT,
		startedAt:    now,
		lastReadAt:   now,
		dest:         dest,
	}
	// Detect initial level (handshake RTT may already be critical)
	stats := mc.statsLocked()
	mc.level = Detect(stats, cfg)
	return mc
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
		c.checkLevel()
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
		c.checkLevel()
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
		"level", stats.Level,
		"write_errors", stats.WriteErrors,
		"read_timeouts", stats.ReadTimeouts,
		"avg_write_latency", stats.AvgWriteLatency,
	)
	if c.OnClose != nil {
		c.OnClose()
	}
	return c.Conn.Close()
}

func (c *MonitoredConn) Level() DegradationLevel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.level
}

func (c *MonitoredConn) IsHealthy() bool {
	return c.Level() == Healthy
}

func (c *MonitoredConn) Stats() ConnStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statsLocked()
}

// must be called under c.mu
func (c *MonitoredConn) statsLocked() ConnStats {
	return ConnStats{
		HandshakeRTT:    c.handshakeRTT,
		WriteErrors:     c.writeErrors,
		ReadTimeouts:    c.readTimeouts,
		TotalRead:       c.totalRead.Load(),
		TotalWritten:    c.totalWritten.Load(),
		Duration:        time.Since(c.startedAt),
		AvgWriteLatency: c.avgWriteLatency(),
		Level:           c.level,
	}
}

// must be called under c.mu. Fires callback outside mutex if level changed.
func (c *MonitoredConn) checkLevel() {
	stats := c.statsLocked()
	newLevel := Detect(stats, c.cfg)
	if newLevel == c.level {
		return
	}
	old := c.level
	c.level = newLevel
	stats.Level = newLevel

	cb := c.OnDegradation
	dest := c.dest
	c.mu.Unlock()

	slog.Warn("tunnel degradation changed", "dest", dest, "from", old, "to", newLevel)
	if cb != nil {
		cb(newLevel, stats)
	}

	c.mu.Lock()
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
