package nidhogg_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/server"
	"github.com/aesleif/nidhogg/pkg/nidhogg"
)

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

func startTestServer(t *testing.T, psk []byte, pm *server.ProfileManager) *httptest.Server {
	t.Helper()
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fallback"))
	})
	handler := server.TunnelHandler(psk, fallback, pm, nil)
	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)
	srv := httptest.NewUnstartedServer(h2cHandler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
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

func TestNewClientValidation(t *testing.T) {
	_, err := nidhogg.NewClient(nidhogg.ClientConfig{})
	if err == nil {
		t.Fatal("expected error for empty config")
	}

	_, err = nidhogg.NewClient(nidhogg.ClientConfig{Server: "host:443"})
	if err == nil {
		t.Fatal("expected error for missing PSK")
	}

	c, err := nidhogg.NewClient(nidhogg.ClientConfig{Server: "host:443", PSK: "secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c.Close()
}

func TestClientDialEcho(t *testing.T) {
	psk := []byte("test-psk")
	echoAddr := startEchoServer(t)
	srv := startTestServer(t, psk, nil)

	host := srv.URL[len("https://"):]
	client, err := nidhogg.NewClient(nidhogg.ClientConfig{
		Server:      host,
		PSK:         string(psk),
		Insecure:    true,
		Fingerprint: "standard",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello via public api")
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

	if conn.HandshakeRTT() == 0 {
		t.Error("expected non-zero HandshakeRTT")
	}
}

func TestClientDialShaped(t *testing.T) {
	psk := []byte("shaped-psk")
	echoAddr := startEchoServer(t)

	pm := server.NewProfileManager([]string{"test"}, time.Hour, 20)
	pm.Push(makeTestProfile())

	srv := startTestServer(t, psk, pm)
	host := srv.URL[len("https://"):]

	client, err := nidhogg.NewClient(nidhogg.ClientConfig{
		Server:      host,
		PSK:         string(psk),
		Insecure:    true,
		Fingerprint: "standard",
		ShapingMode: nidhogg.ShapingBalanced,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	conn, err := client.Dial(context.Background(), echoAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if conn.Profile().Name != "test-profile" {
		t.Errorf("Profile().Name = %q, want %q", conn.Profile().Name, "test-profile")
	}

	msg := []byte("shaped data via public api")
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

func TestClientDialWrongPSK(t *testing.T) {
	psk := []byte("correct-psk")
	srv := startTestServer(t, psk, nil)
	host := srv.URL[len("https://"):]

	client, err := nidhogg.NewClient(nidhogg.ClientConfig{
		Server:      host,
		PSK:         "wrong-psk",
		Insecure:    true,
		Fingerprint: "standard",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	_, err = client.Dial(context.Background(), "127.0.0.1:9999")
	if err == nil {
		t.Fatal("expected error with wrong PSK")
	}
}
