package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/aesleif/nidhogg/internal/client"
	"github.com/aesleif/nidhogg/internal/server"
)

// startEchoServer starts a TCP server that echoes all received data back.
func startEchoServer(t *testing.T) string {
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
				io.Copy(conn, conn)
			}()
		}
	}()

	return ln.Addr().String()
}

// startTunnelServer starts an httptest TLS server with TunnelHandler.
func startTunnelServer(t *testing.T, psk []byte) *httptest.Server {
	t.Helper()

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})

	handler := server.TunnelHandler(psk, fallback, nil)

	// Use h2c for testing (HTTP/2 without TLS) to avoid cert setup complexity
	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)

	srv := httptest.NewUnstartedServer(h2cHandler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// newTestDialer creates a Dialer pointed at the test server.
func newTestDialer(t *testing.T, srv *httptest.Server, psk []byte) *client.Dialer {
	t.Helper()
	// Extract host:port from test server URL (strip https://)
	host := srv.URL[len("https://"):]
	return client.NewDialer(host, "/", psk, true, "standard")
}

func TestTunnelEcho(t *testing.T) {
	psk := []byte("test-psk-key")
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, psk)
	dialer := newTestDialer(t, srv, psk)

	conn, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// Write data and read echo
	msg := []byte("hello nidhogg")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Errorf("echo = %q, want %q", buf, msg)
	}
}

func TestTunnelWrongPSK(t *testing.T) {
	psk := []byte("correct-psk")
	startEchoServer(t) // not used, but keeps the pattern consistent
	srv := startTunnelServer(t, psk)
	dialer := newTestDialer(t, srv, []byte("wrong-psk-key"))

	_, _, err := dialer.DialTunnel(context.Background(), "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected error with wrong PSK, got nil")
	}
}

func TestTunnelMultiplex(t *testing.T) {
	psk := []byte("multiplex-psk")
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, psk)
	dialer := newTestDialer(t, srv, psk)

	const numConns = 10
	var wg sync.WaitGroup
	errors := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, _, err := dialer.DialTunnel(context.Background(), echoAddr)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()

			msg := []byte("hello from goroutine")
			if _, err := conn.Write(msg); err != nil {
				errors <- err
				return
			}

			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errors <- err
				return
			}

			if !bytes.Equal(buf, msg) {
				errors <- io.ErrUnexpectedEOF
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("multiplex error: %v", err)
	}
}

func TestTunnelLargeTransfer(t *testing.T) {
	psk := []byte("large-psk")
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, psk)
	dialer := newTestDialer(t, srv, psk)

	conn, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// Send 1MB of random data
	const size = 1 << 20
	data := make([]byte, size)
	rand.Read(data)

	// Write in a goroutine, read in main
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn.Write(data)
	}()

	received := make([]byte, size)
	if _, err := io.ReadFull(conn, received); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	wg.Wait()

	if !bytes.Equal(received, data) {
		t.Error("large transfer data mismatch")
	}
}
