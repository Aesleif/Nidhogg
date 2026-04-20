package server

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aesleif/nidhogg/internal/transport"
)

const (
	// peekTimeout bounds how long we wait for the start of a TLS
	// ClientHello before giving up — protects against slow-loris probes.
	peekTimeout = 5 * time.Second
	// tlsRecordHeader is type(1) + version(2) + length(2).
	tlsRecordHeader = 5
	// maxRecordBody is the per-RFC TLS record body max (2^14 plus a bit
	// of padding for compressed records — but plaintext handshake records
	// are well under).
	maxRecordBody = 1 << 14
	// dialTimeout caps how long the cover upstream connection setup may
	// take before we drop the probe.
	dialTimeout = 10 * time.Second
)

// HandlerFunc receives a connection that has been classified as belonging
// to the nidhogg protocol (SNI matches our domain). The peeked ClientHello
// bytes are still available via Read on the conn — the handler should
// hand the conn straight to a TLS-terminating server.
type HandlerFunc func(net.Conn)

// SNIRouter listens for incoming TCP connections, peeks at the TLS
// ClientHello to classify each, and either:
//   - hands matching-SNI connections to NidhoggHandler (TLS termination
//     happens there)
//   - raw-TCP-forwards everything else to CoverUpstream
//
// This protects against IP-range scanners that probe with arbitrary SNIs
// (e.g., google.com, microsoft.com) by serving them the real upstream's
// certificate and TLS handshake byte-for-byte. Probes targeted at our
// actual domain still go through the regular nidhogg path; that class of
// probe needs a Phase-2 cert-mux solution to mask.
type SNIRouter struct {
	OurDomain      string      // SNI value that maps to NidhoggHandler
	CoverUpstream  string      // host:port to raw-forward unrelated traffic to
	NidhoggHandler HandlerFunc // called for matching SNI
}

// Serve accepts connections from ln and dispatches each in its own
// goroutine. It blocks until ln returns an error.
func (r *SNIRouter) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go r.handle(conn)
	}
}

func (r *SNIRouter) handle(conn net.Conn) {
	pc := transport.NewPeekConn(conn)

	_ = conn.SetReadDeadline(time.Now().Add(peekTimeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	// Peek the TLS record header first to learn the actual record length,
	// then peek exactly that much. Avoids blocking on a fixed-size read
	// when the ClientHello is shorter than the buffer.
	hdr, err := pc.Peek(tlsRecordHeader)
	if err != nil || len(hdr) < tlsRecordHeader {
		conn.Close()
		return
	}
	if hdr[0] != 22 { // not a TLS handshake record
		conn.Close()
		return
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > maxRecordBody {
		conn.Close()
		return
	}

	full, err := pc.Peek(tlsRecordHeader + recLen)
	if err != nil {
		conn.Close()
		return
	}

	sni, alpn, parseErr := transport.PeekSNI(full)
	if parseErr != nil && !errors.Is(parseErr, transport.ErrShortBuffer) {
		conn.Close()
		return
	}

	// ACME TLS-ALPN-01 challenge: route to nidhogg path so autocert can
	// answer with its challenge cert (matched by ALPN inside autocert's
	// GetCertificate).
	if slices.Contains(alpn, "acme-tls/1") {
		r.NidhoggHandler(pc)
		return
	}

	if strings.EqualFold(sni, r.OurDomain) {
		r.NidhoggHandler(pc)
		return
	}

	rawTCPForward(pc, r.CoverUpstream)
}

// rawTCPForward dials upstream and copies bytes both ways with idempotent
// cleanup so neither direction can leak goroutines on the other's exit.
func rawTCPForward(client net.Conn, upstream string) {
	up, err := net.DialTimeout("tcp", upstream, dialTimeout)
	if err != nil {
		slog.Debug("snirouter: cover upstream dial failed", "addr", upstream, "err", err)
		client.Close()
		return
	}

	var (
		wg       sync.WaitGroup
		closed   sync.Once
		closeAll = func() {
			closed.Do(func() {
				client.Close()
				up.Close()
			})
		}
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeAll()
		_, _ = io.Copy(up, client)
	}()
	go func() {
		defer wg.Done()
		defer closeAll()
		_, _ = io.Copy(client, up)
	}()
	wg.Wait()
}

// SingleConnListener implements net.Listener and yields exactly one conn,
// then returns io.EOF on subsequent Accept. Useful for handing a single
// already-accepted connection to an http.Server (which insists on having
// a listener).
type SingleConnListener struct {
	conn net.Conn
	done chan struct{}
	once sync.Once
}

// NewSingleConnListener wraps c.
func NewSingleConnListener(c net.Conn) *SingleConnListener {
	return &SingleConnListener{conn: c, done: make(chan struct{})}
}

func (l *SingleConnListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, io.EOF
	default:
	}
	c := l.conn
	l.conn = nil
	l.once.Do(func() { close(l.done) })
	if c == nil {
		<-l.done
		return nil, io.EOF
	}
	return c, nil
}

func (l *SingleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *SingleConnListener) Addr() net.Addr {
	if l.conn != nil {
		return l.conn.LocalAddr()
	}
	return &net.TCPAddr{IP: net.IPv4zero}
}
