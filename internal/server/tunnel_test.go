package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/aesleif/nidhogg/internal/client"
	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/transport"
)

// testKeypair generates a fresh Ed25519 keypair for the test. Each test
// gets an independent pair; production key material never appears here.
func testKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

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

// startTunnelServer starts an httptest TLS server with TunnelHandler
// accepting the given public key as the only authorized client.
func startTunnelServer(t *testing.T, pub ed25519.PublicKey) *httptest.Server {
	return startTunnelServerWithPM(t, pub, nil)
}

func startTunnelServerWithPM(t *testing.T, pub ed25519.PublicKey, pm *server.ProfileManager) *httptest.Server {
	t.Helper()

	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})

	auth := transport.NewAuthStore([]ed25519.PublicKey{pub}, []string{"test"})
	handler := server.TunnelHandler(auth, server.NopDestChecker{}, fallback, pm, nil)

	// Use h2c for testing (HTTP/2 without TLS) to avoid cert setup complexity
	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)

	srv := httptest.NewUnstartedServer(h2cHandler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// newTestDialer creates a Dialer pointed at the test server signing
// handshakes with priv.
func newTestDialer(t *testing.T, srv *httptest.Server, priv ed25519.PrivateKey) *client.Dialer {
	return newTestDialerWithShaping(t, srv, priv, shaper.Disabled)
}

func newTestDialerWithShaping(t *testing.T, srv *httptest.Server, priv ed25519.PrivateKey, mode shaper.ShapingMode) *client.Dialer {
	t.Helper()
	host := srv.URL[len("https://"):]
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return client.NewDialer(host, "/", priv, pool, "standard", mode, 1, 0, 0)
}

func makeTestProfile() *profile.Profile {
	base := time.Now()
	snap := &pcap.TrafficSnapshot{
		Target:    "test",
		Duration:  time.Second,
		CreatedAt: base,
		Samples: []pcap.PacketSample{
			{Size: 200, Direction: true, Timestamp: base},
			{Size: 400, Direction: false, Timestamp: base.Add(5 * time.Millisecond)},
			{Size: 300, Direction: true, Timestamp: base.Add(10 * time.Millisecond)},
			{Size: 800, Direction: false, Timestamp: base.Add(15 * time.Millisecond)},
			{Size: 1200, Direction: true, Timestamp: base.Add(20 * time.Millisecond)},
		},
	}
	return profile.Generate("test-profile", []*pcap.TrafficSnapshot{snap})
}

func TestTunnelEchoShaped(t *testing.T) {
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)

	pm := server.NewProfileManager([]string{"test"}, time.Hour, 20)
	pm.Push(makeTestProfile())

	srv := startTunnelServerWithPM(t, pub, pm)
	dialer := newTestDialerWithShaping(t, srv, priv, shaper.Balanced)

	conn, prof, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	if prof == nil {
		t.Fatal("expected profile from server, got nil")
	}
	if prof.Name != "test-profile" {
		t.Errorf("profile name = %q, want %q", prof.Name, "test-profile")
	}

	msg := []byte("hello shaped tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("shaped echo = %q, want %q", buf, msg)
	}
}

// TestTunnelClosesUpstreamWhenClientDisconnects covers a goroutine leak:
// when the client closes its side of the tunnel but the upstream is alive
// and silent (e.g. websocket / MTProto idle), the response-direction
// goroutine used to block on upstream.Read forever — wedging wg.Wait,
// preventing defer tcpUpstream.Close, and leaking the TCP socket plus
// frame buffers per dead client. The fix closes the upstream as soon as
// either relay direction exits.
func TestTunnelClosesUpstreamWhenClientDisconnects(t *testing.T) {
	pub, priv := testKeypair(t)

	// Silent upstream: accept, read into the void, but never write.
	// We signal `closed` from inside Accept's goroutine so the test can
	// wait for the server to drop us.
	silentLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer silentLn.Close()

	closed := make(chan struct{})
	go func() {
		conn, err := silentLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			if _, err := conn.Read(buf); err != nil {
				close(closed)
				return
			}
		}
	}()

	srv := startTunnelServer(t, pub)
	dialer := newTestDialer(t, srv, priv)

	conn, _, _, err := dialer.DialTunnel(context.Background(), silentLn.Addr().String())
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}

	// Send a byte so the upstream goroutine is definitely sitting in Read.
	if _, err := conn.Write([]byte{0x42}); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Close the client side. With the fix, server's first relay direction
	// exits (r.Body returns io.EOF), runs deferred closeUpstream, the
	// silent upstream sees io.EOF on its Read, and signals `closed`.
	// Without the fix, the server's response-direction goroutine sits
	// on upstream.Read indefinitely → upstream stays open → no signal.
	conn.Close()

	select {
	case <-closed:
		// pass
	case <-time.After(3 * time.Second):
		t.Fatal("upstream connection was never closed by server — relay goroutine leaked")
	}
}

// TestTunnelEchoShapedSecondCall covers the regression where the dialer
// dropped the parsed profile on the second call (server skipped JSON via
// version cache → prof returned nil → client unwrapped ShapedConn while
// the server was still framing). The dialer must keep the profile cached.
func TestTunnelEchoShapedSecondCall(t *testing.T) {
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)

	pm := server.NewProfileManager([]string{"test"}, time.Hour, 20)
	pm.Push(makeTestProfile())

	srv := startTunnelServerWithPM(t, pub, pm)
	dialer := newTestDialerWithShaping(t, srv, priv, shaper.Balanced)

	// First call: server delivers profile JSON, dialer caches it.
	conn1, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("first DialTunnel: %v", err)
	}
	conn1.Close()

	// Second call: server sees matching version, sends size=0. Without
	// the cache the dialer would return a raw conn while the server
	// keeps framing → echo would be corrupted.
	conn2, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("second DialTunnel: %v", err)
	}
	defer conn2.Close()

	msg := []byte("second call still shaped")
	if _, err := conn2.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn2, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Errorf("second-call echo = %q, want %q", buf, msg)
	}
}

// TestTunnelEchoUDPWithShaping covers the regression where the dialer
// wrapped UDP destinations in ShapedConn even though the server's UDP
// path bypasses shaping. The two framing layers (shaper frames vs UDP
// length-prefix datagrams) collided and corrupted every packet.
func TestTunnelEchoUDPWithShaping(t *testing.T) {
	pub, priv := testKeypair(t)

	// Echo server that reads UDP datagrams and bounces them back.
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			udpLn.WriteTo(buf[:n], addr)
		}
	}()

	pm := server.NewProfileManager([]string{"test"}, time.Hour, 20)
	pm.Push(makeTestProfile())

	srv := startTunnelServerWithPM(t, pub, pm)
	dialer := newTestDialerWithShaping(t, srv, priv, shaper.Balanced)

	conn, _, _, err := dialer.DialTunnel(context.Background(), "udp:"+udpLn.LocalAddr().String())
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	// UDP framing from the public API expects [2B length][payload].
	msg := []byte("udp ping under shaping")
	frame := make([]byte, 2+len(msg))
	frame[0] = byte(len(msg) >> 8)
	frame[1] = byte(len(msg))
	copy(frame[2:], msg)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write frame: %v", err)
	}

	respHdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, respHdr); err != nil {
		t.Fatalf("read response header: %v", err)
	}
	respLen := int(respHdr[0])<<8 | int(respHdr[1])
	if respLen != len(msg) {
		t.Fatalf("response length = %d, want %d", respLen, len(msg))
	}
	respPayload := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respPayload); err != nil {
		t.Fatalf("read response payload: %v", err)
	}
	if !bytes.Equal(respPayload, msg) {
		t.Errorf("udp echo = %q, want %q", respPayload, msg)
	}
}

// TestTunnelEchoServerProfileClientNoShape covers the regression where the
// server unconditionally framed the relay whenever a profile was active,
// while a client with shaping disabled sent raw bytes — corrupting both
// directions. The fix is for the server to only frame when the client
// signals it will too.
func TestTunnelEchoServerProfileClientNoShape(t *testing.T) {
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)

	pm := server.NewProfileManager([]string{"test"}, time.Hour, 20)
	pm.Push(makeTestProfile())

	srv := startTunnelServerWithPM(t, pub, pm)
	dialer := newTestDialerWithShaping(t, srv, priv, shaper.Disabled)

	conn, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("DialTunnel: %v", err)
	}
	defer conn.Close()

	msg := []byte("raw client, profile-bearing server")
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

func TestTunnelEcho(t *testing.T) {
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, pub)
	dialer := newTestDialer(t, srv, priv)

	conn, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
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

func TestTunnelWrongKey(t *testing.T) {
	pub, _ := testKeypair(t)
	_, wrongPriv := testKeypair(t) // unrelated keypair — pubkey not authorized
	srv := startTunnelServer(t, pub)
	dialer := newTestDialer(t, srv, wrongPriv)

	_, _, _, err := dialer.DialTunnel(context.Background(), "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected error with unknown pubkey, got nil")
	}
}

func TestTunnelMultiplex(t *testing.T) {
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, pub)
	dialer := newTestDialer(t, srv, priv)

	const numConns = 10
	var wg sync.WaitGroup
	errors := make(chan error, numConns)

	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
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
	pub, priv := testKeypair(t)
	echoAddr := startEchoServer(t)
	srv := startTunnelServer(t, pub)
	dialer := newTestDialer(t, srv, priv)

	conn, _, _, err := dialer.DialTunnel(context.Background(), echoAddr)
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
