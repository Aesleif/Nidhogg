package server

import (
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startCoverUpstream stands in for a real HTTPS site: accepts TCP, sends
// a marker line so the test can verify the proxied client got real
// upstream bytes.
func startCoverUpstream(t *testing.T, marker string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte(marker))
				// Drain client bytes (ClientHello) so peer Write doesn't block
				buf := make([]byte, 4096)
				for {
					if _, err := conn.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func sendClientHello(t *testing.T, addr, sni string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	uc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	// Don't wait for full handshake — just drive ClientHello write.
	go func() { _ = uc.Handshake() }()
	return conn
}

func TestSNIRouterForwardsMismatchedSNI(t *testing.T) {
	upstream := startCoverUpstream(t, "MICROSOFT_BANNER\n")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var nidhoggCalled atomic.Int32
	router := &SNIRouter{
		OurDomain:     "tunnel.example.com",
		CoverUpstream: upstream,
		NidhoggHandler: func(c net.Conn) {
			nidhoggCalled.Add(1)
			c.Close()
		},
	}
	go router.Serve(ln)

	conn := sendClientHello(t, ln.Addr().String(), "www.microsoft.com")
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len("MICROSOFT_BANNER\n"))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "MICROSOFT_BANNER") {
		t.Errorf("forwarded read = %q, want contains MICROSOFT_BANNER", got)
	}
	if nidhoggCalled.Load() != 0 {
		t.Errorf("nidhogg handler was called for mismatched SNI")
	}
}

func TestSNIRouterDispatchesMatchingSNI(t *testing.T) {
	upstream := startCoverUpstream(t, "WRONG_PATH\n")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	handed := make(chan net.Conn, 1)
	router := &SNIRouter{
		OurDomain:     "tunnel.example.com",
		CoverUpstream: upstream,
		NidhoggHandler: func(c net.Conn) {
			handed <- c
		},
	}
	go router.Serve(ln)

	conn := sendClientHello(t, ln.Addr().String(), "tunnel.example.com")
	defer conn.Close()

	select {
	case c := <-handed:
		// Verify the peeked bytes are still readable: read first 5 bytes
		// must be a TLS record header (type=22, version=03 0X).
		buf := make([]byte, 5)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("nidhogg conn read: %v", err)
		}
		if n < 5 || buf[0] != 22 {
			t.Errorf("first bytes = %x, want TLS handshake record (type 22)", buf[:n])
		}
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("nidhogg handler was not called for matching SNI")
	}
}

func TestSNIRouterRejectsNonTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	router := &SNIRouter{
		OurDomain:     "tunnel.example.com",
		CoverUpstream: "127.0.0.1:9", // discard port — won't be reached
		NidhoggHandler: func(c net.Conn) {
			t.Error("nidhogg handler should not be called for non-TLS")
			c.Close()
		},
	}
	go router.Serve(ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected EOF/timeout, conn should be dropped")
	}
}
