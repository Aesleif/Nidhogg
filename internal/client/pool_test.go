package client

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// startH2CServer returns an httptest server speaking h2c (HTTP/2 cleartext)
// and the addr to dial. The handler always returns 200 OK.
func startH2CServer(t *testing.T) string {
	t.Helper()
	h2s := &http2.Server{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(h2c.NewHandler(handler, h2s))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")
	return addr
}

// rawDialer dials a plain TCP connection to addr (no TLS, paired with h2c).
func rawDialer(t *testing.T, addr string) (DialFn, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		calls.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	return dial, &calls
}

func newTransport() *http2.Transport {
	return &http2.Transport{
		AllowHTTP: true,
		// h2c: skip TLS in NewClientConn path.
	}
}

func TestPoolCreatesUpToSize(t *testing.T) {
	addr := startH2CServer(t)
	tr := newTransport()
	dial, calls := rawDialer(t, addr)
	pool := NewConnPool(tr, 3, 0, dial)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
	for i := 0; i < 3; i++ {
		cc, err := pool.GetClientConn(req, addr)
		if err != nil {
			t.Fatalf("GetClientConn[%d]: %v", i, err)
		}
		// Release the reservation so the conn is available for the next call.
		cc.RoundTrip(req)
	}

	if got := calls.Load(); got != 3 {
		t.Errorf("dial calls = %d, want 3", got)
	}
}

func TestPoolRoundRobins(t *testing.T) {
	addr := startH2CServer(t)
	tr := newTransport()
	dial, _ := rawDialer(t, addr)
	pool := NewConnPool(tr, 3, 0, dial)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)

	// Warm up the pool.
	seen := map[*http2.ClientConn]int{}
	for i := 0; i < 3; i++ {
		cc, err := pool.GetClientConn(req, addr)
		if err != nil {
			t.Fatalf("warmup[%d]: %v", i, err)
		}
		seen[cc]++
		cc.RoundTrip(req)
	}
	if len(seen) != 3 {
		t.Fatalf("warmup gave %d distinct conns, want 3", len(seen))
	}

	// Subsequent calls must round-robin across all three.
	post := map[*http2.ClientConn]int{}
	for i := 0; i < 9; i++ {
		cc, err := pool.GetClientConn(req, addr)
		if err != nil {
			t.Fatalf("rr[%d]: %v", i, err)
		}
		post[cc]++
		cc.RoundTrip(req)
	}
	if len(post) != 3 {
		t.Errorf("round-robin hit %d conns, want 3", len(post))
	}
	for cc, n := range post {
		if n != 3 {
			t.Errorf("conn %p got %d hits, want 3", cc, n)
		}
	}
}

func TestPoolMarkDeadRemoves(t *testing.T) {
	addr := startH2CServer(t)
	tr := newTransport()
	dial, calls := rawDialer(t, addr)
	pool := NewConnPool(tr, 2, 0, dial)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)

	cc1, err := pool.GetClientConn(req, addr)
	if err != nil {
		t.Fatalf("first GetClientConn: %v", err)
	}
	cc1.RoundTrip(req)
	cc2, err := pool.GetClientConn(req, addr)
	if err != nil {
		t.Fatalf("second GetClientConn: %v", err)
	}
	cc2.RoundTrip(req)
	if calls.Load() != 2 {
		t.Fatalf("dial calls = %d, want 2", calls.Load())
	}

	// Kill one conn and mark it dead. The next call must redial to refill.
	cc1.Close()
	pool.MarkDead(cc1)

	cc3, err := pool.GetClientConn(req, addr)
	if err != nil {
		t.Fatalf("third GetClientConn: %v", err)
	}
	cc3.RoundTrip(req)
	if calls.Load() != 3 {
		t.Errorf("dial calls after MarkDead = %d, want 3", calls.Load())
	}
	if cc3 == cc1 {
		t.Error("got back the dead conn after MarkDead")
	}
}

func TestPoolConcurrentGet(t *testing.T) {
	addr := startH2CServer(t)
	tr := newTransport()
	dial, calls := rawDialer(t, addr)
	pool := NewConnPool(tr, 4, 0, dial)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cc, err := pool.GetClientConn(req, addr)
			if err != nil {
				t.Errorf("GetClientConn: %v", err)
				return
			}
			cc.RoundTrip(req)
		}()
	}
	wg.Wait()

	// Should have dialed at most pool size, regardless of concurrency.
	if got := calls.Load(); got > 4 {
		t.Errorf("dial calls = %d, want ≤ 4", got)
	}
}

// TestPoolRecyclesAfterMaxAge verifies that connections older than maxAge
// are dropped from the pool and replaced with fresh ones, addressing the
// gradual latency degradation that comes from long-lived ClientConns
// accumulating internal h2 state and riding stale TCP paths.
func TestPoolRecyclesAfterMaxAge(t *testing.T) {
	addr := startH2CServer(t)
	tr := newTransport()
	dial, calls := rawDialer(t, addr)

	maxAge := 100 * time.Millisecond
	pool := NewConnPool(tr, 2, maxAge, dial)

	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)

	// Warm: dial 2 conns.
	for i := 0; i < 2; i++ {
		cc, err := pool.GetClientConn(req, addr)
		if err != nil {
			t.Fatalf("warmup[%d]: %v", i, err)
		}
		cc.RoundTrip(req)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("warmup dials = %d, want 2", got)
	}

	// Wait past maxAge so existing conns are due for recycling.
	time.Sleep(maxAge + 50*time.Millisecond)

	// Next 2 calls should trigger fresh dials (old conns retired async).
	for i := 0; i < 2; i++ {
		cc, err := pool.GetClientConn(req, addr)
		if err != nil {
			t.Fatalf("post-age[%d]: %v", i, err)
		}
		cc.RoundTrip(req)
	}
	if got := calls.Load(); got != 4 {
		t.Errorf("dials after maxAge = %d, want 4", got)
	}
}
