package transport

import (
	"net"
	"sync"
	"time"
)

// IdleConn wraps a net.Conn and closes it after `timeout` of no Read/Write
// activity. This bounds the lifetime of "half-dead" tunnels where neither
// peer signals close (NAT timeout, RST lost, silent upstream waiting on a
// silent source) so that goroutines blocked on Read can finally unblock
// with an error and let the surrounding handler clean up.
//
// Cost per conn: one *time.Timer (no extra goroutine until it fires).
type IdleConn struct {
	net.Conn
	timeout time.Duration

	mu           sync.Mutex
	timer        *time.Timer
	closed       bool
	lastActivity time.Time
}

// NewIdleConn wraps c. Activity (any successful Read or Write of >0 bytes)
// pushes the deadline forward. If timeout is <= 0, c is returned bare.
func NewIdleConn(c net.Conn, timeout time.Duration) net.Conn {
	if timeout <= 0 {
		return c
	}
	ic := &IdleConn{Conn: c, timeout: timeout, lastActivity: time.Now()}
	ic.timer = time.AfterFunc(timeout, ic.onIdle)
	return ic
}

func (c *IdleConn) bump() {
	c.mu.Lock()
	if !c.closed {
		c.lastActivity = time.Now()
		c.timer.Reset(c.timeout)
	}
	c.mu.Unlock()
}

func (c *IdleConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bump()
	}
	return n, err
}

func (c *IdleConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bump()
	}
	return n, err
}

func (c *IdleConn) Close() error {
	c.mu.Lock()
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	return c.Conn.Close()
}

// onIdle fires when timeout elapses without activity. It closes the
// underlying conn (which unblocks any Read/Write on either side) and
// marks closed so a racing bump from in-flight I/O is a no-op.
//
// Handles the bump/onIdle race: if bump() ran after the runtime scheduled
// this callback, timer.Reset could not cancel the already-in-flight
// callback. Without the lastActivity re-check, onIdle would close a
// connection that had fresh I/O just microseconds before firing. Instead,
// if activity happened within the timeout, reschedule the timer for the
// remaining slack and don't close.
func (c *IdleConn) onIdle() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	elapsed := time.Since(c.lastActivity)
	if elapsed < c.timeout {
		c.timer.Reset(c.timeout - elapsed)
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()
	c.Conn.Close()
}
