package pcap

import (
	"net"
	"sync"
	"time"
)

// maxSamples caps the per-connection sample buffer. CDF generation needs
// only a few hundred samples; further entries waste memory on long-lived
// tunnels (websockets, large downloads) which would otherwise grow the
// slice indefinitely.
const maxSamples = 10_000

// PacketSample records the size and direction of a single read/write operation.
type PacketSample struct {
	Size      int
	Direction bool // true = sent (Write), false = received (Read)
	Timestamp time.Time
}

// TrafficSnapshot holds all samples collected during a recording session.
type TrafficSnapshot struct {
	Samples   []PacketSample
	Target    string
	Duration  time.Duration
	CreatedAt time.Time
}

// RecordingConn wraps a net.Conn and records the size of every Read and Write.
type RecordingConn struct {
	net.Conn
	mu      sync.Mutex
	samples []PacketSample
}

// NewRecordingConn wraps conn in a recording layer.
func NewRecordingConn(conn net.Conn) *RecordingConn {
	return &RecordingConn{Conn: conn}
}

func (c *RecordingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if len(c.samples) < maxSamples {
			c.samples = append(c.samples, PacketSample{
				Size:      n,
				Direction: false,
				Timestamp: time.Now(),
			})
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *RecordingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.mu.Lock()
		if len(c.samples) < maxSamples {
			c.samples = append(c.samples, PacketSample{
				Size:      n,
				Direction: true,
				Timestamp: time.Now(),
			})
		}
		c.mu.Unlock()
	}
	return n, err
}

// Samples returns a copy of all recorded samples.
func (c *RecordingConn) Samples() []PacketSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]PacketSample, len(c.samples))
	copy(out, c.samples)
	return out
}
