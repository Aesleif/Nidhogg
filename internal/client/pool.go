package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"golang.org/x/net/http2"
)

// DialFn dials a fresh TCP+TLS connection to addr that has already
// negotiated h2 via ALPN.
type DialFn func(ctx context.Context, network, addr string) (net.Conn, error)

// ConnPool keeps up to size live HTTP/2 connections per server addr and
// round-robins new requests across them. This mitigates TCP head-of-line
// blocking that would otherwise stall every multiplexed stream when one
// of them experiences packet loss on the single shared TCP socket.
//
// It implements http2.ClientConnPool.
type ConnPool struct {
	transport *http2.Transport
	size      int
	dial      DialFn

	mu       sync.Mutex
	conns    map[string][]*http2.ClientConn
	counters map[string]*atomic.Uint64
}

// NewConnPool returns a ConnPool that dials up to size connections per addr
// using dial. If size <= 0, it defaults to 1 (matching default h2 behavior).
func NewConnPool(t *http2.Transport, size int, dial DialFn) *ConnPool {
	if size <= 0 {
		size = 1
	}
	return &ConnPool{
		transport: t,
		size:      size,
		dial:      dial,
		conns:     make(map[string][]*http2.ClientConn),
		counters:  make(map[string]*atomic.Uint64),
	}
}

// GetClientConn returns a live ClientConn for addr, reserving a stream slot
// on it. It dials new connections lazily up to the pool size.
func (p *ConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Drop dead/saturated connections. Allocate a fresh slice rather
	// than reslicing in place — `p.conns[addr][:0]` would keep the dead
	// pointers in the underlying array's tail past len, preventing the
	// GC from reclaiming the ClientConn structs (each holds the TLS
	// conn, frame buffers, stream map, HPACK state — easily hundreds of
	// KB live).
	prev := p.conns[addr]
	alive := make([]*http2.ClientConn, 0, p.size)
	for _, cc := range prev {
		if cc.CanTakeNewRequest() {
			alive = append(alive, cc)
		}
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
		alive = append(alive, cc)
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
	cc := alive[idx]

	// ClientConnPool contract: must reserve a stream slot before returning.
	if !cc.ReserveNewRequest() {
		// Highly unlikely after the CanTakeNewRequest filter above, but
		// guard against the race where the conn fills up between the two
		// checks. Try the others.
		for offset := 1; offset < len(alive); offset++ {
			candidate := alive[(idx+offset)%len(alive)]
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
		// `list[:0]` would leak ClientConn memory through the array's
		// tail.
		kept := make([]*http2.ClientConn, 0, len(list))
		for _, c := range list {
			if c != cc {
				kept = append(kept, c)
			}
		}
		p.conns[addr] = kept
	}
}
