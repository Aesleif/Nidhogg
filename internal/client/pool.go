package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// DialFn dials a fresh TCP+TLS connection to addr that has already
// negotiated h2 via ALPN.
type DialFn func(ctx context.Context, network, addr string) (net.Conn, error)

// shutdownGrace bounds how long a recycled ClientConn waits for in-flight
// streams to finish before being force-closed.
const shutdownGrace = 30 * time.Second

// pooledConn pairs an *http2.ClientConn with the time it was dialed so the
// pool can recycle connections that exceed the configured max age.
type pooledConn struct {
	cc     *http2.ClientConn
	bornAt time.Time
}

// ConnPool keeps up to size live HTTP/2 connections per server addr and
// round-robins new requests across them. This mitigates TCP head-of-line
// blocking that would otherwise stall every multiplexed stream when one
// of them experiences packet loss on the single shared TCP socket.
//
// Optional `maxAge` retires connections older than that and forces redial.
// Without recycling, long-lived ClientConns accumulate internal h2 state
// (streams map, frame queues, HPACK tables) that grows but never shrinks,
// and ride a TCP path whose congestion window may have drifted away from
// current network conditions — leading to gradual latency degradation.
//
// It implements http2.ClientConnPool.
type ConnPool struct {
	transport *http2.Transport
	size      int
	maxAge    time.Duration
	dial      DialFn

	mu       sync.Mutex
	conns    map[string][]*pooledConn
	counters map[string]*atomic.Uint64
}

// NewConnPool returns a ConnPool that dials up to size connections per addr
// using dial. If size <= 0, it defaults to 1 (matching default h2 behavior).
// If maxAge <= 0, connections live until h2 itself drops them.
func NewConnPool(t *http2.Transport, size int, maxAge time.Duration, dial DialFn) *ConnPool {
	if size <= 0 {
		size = 1
	}
	return &ConnPool{
		transport: t,
		size:      size,
		maxAge:    maxAge,
		dial:      dial,
		conns:     make(map[string][]*pooledConn),
		counters:  make(map[string]*atomic.Uint64),
	}
}

// GetClientConn returns a live ClientConn for addr, reserving a stream slot
// on it. It dials new connections lazily up to the pool size and asynchronously
// recycles connections older than maxAge.
func (p *ConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := p.conns[addr]
	now := time.Now()

	// Allocate a fresh slice rather than reslicing in place — `prev[:0]`
	// would keep the dead pointers in the underlying array's tail past
	// len, preventing the GC from reclaiming the ClientConn structs.
	alive := make([]*pooledConn, 0, p.size)
	for _, pc := range prev {
		if !pc.cc.CanTakeNewRequest() {
			continue
		}
		if p.maxAge > 0 && now.Sub(pc.bornAt) >= p.maxAge {
			// Too old — gracefully retire (refuse new streams, wait for
			// existing to drain, then force-close). Do this off the hot
			// path so request latency isn't penalized.
			go shutdownConn(pc.cc)
			continue
		}
		alive = append(alive, pc)
	}

	// Dial up to size. If at least one alive conn already exists we
	// degrade gracefully on dial errors instead of failing the request.
	var lastErr error
	for len(alive) < p.size {
		ctx := req.Context()
		raw, err := p.dial(ctx, "tcp", addr)
		if err != nil {
			lastErr = err
			break
		}
		cc, err := p.transport.NewClientConn(raw)
		if err != nil {
			raw.Close()
			lastErr = err
			break
		}
		alive = append(alive, &pooledConn{cc: cc, bornAt: time.Now()})
	}
	p.conns[addr] = alive

	if len(alive) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("nidhogg: no available HTTP/2 connection")
	}

	counter, ok := p.counters[addr]
	if !ok {
		counter = &atomic.Uint64{}
		p.counters[addr] = counter
	}
	idx := int(counter.Add(1)-1) % len(alive)
	cc := alive[idx].cc

	// ClientConnPool contract: must reserve a stream slot before returning.
	if !cc.ReserveNewRequest() {
		// Highly unlikely after the CanTakeNewRequest filter above, but
		// guard against the race where the conn fills up between the two
		// checks. Try the others.
		for offset := 1; offset < len(alive); offset++ {
			candidate := alive[(idx+offset)%len(alive)].cc
			if candidate.ReserveNewRequest() {
				return candidate, nil
			}
		}
		return nil, errors.New("nidhogg: all pooled connections saturated")
	}
	return cc, nil
}

// MarkDead removes cc from the pool. The next GetClientConn that finds
// the pool short of size will redial.
func (p *ConnPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, list := range p.conns {
		// Fresh slice — see the rationale above GetClientConn for why
		// reslicing in place would leak ClientConn memory through the
		// array's tail.
		kept := make([]*pooledConn, 0, len(list))
		for _, pc := range list {
			if pc.cc != cc {
				kept = append(kept, pc)
			}
		}
		p.conns[addr] = kept
	}
}

// shutdownConn drains an outdated ClientConn: refuse new streams, let the
// existing ones run for up to shutdownGrace, then close hard.
func shutdownConn(cc *http2.ClientConn) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	_ = cc.Shutdown(ctx)
	cc.Close()
}
