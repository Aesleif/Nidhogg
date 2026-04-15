package pcap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRecordingConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	rec := NewRecordingConn(client)
	defer rec.Close()

	// Write from recorder side, read on server side
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		// Echo back
		server.Write(buf[:n])
	}()

	msg := []byte("hello recorder")
	if _, err := rec.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 64)
	n, err := rec.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello recorder" {
		t.Errorf("got %q, want %q", buf[:n], "hello recorder")
	}

	samples := rec.Samples()
	if len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %d", len(samples))
	}

	// First sample: Write (sent)
	if samples[0].Direction != true {
		t.Error("first sample should be sent (Direction=true)")
	}
	if samples[0].Size != len(msg) {
		t.Errorf("first sample size = %d, want %d", samples[0].Size, len(msg))
	}

	// Second sample: Read (received)
	if samples[1].Direction != false {
		t.Error("second sample should be received (Direction=false)")
	}
	if samples[1].Size != len(msg) {
		t.Errorf("second sample size = %d, want %d", samples[1].Size, len(msg))
	}
}

func TestCollect(t *testing.T) {
	// Create a TLS test server with a large-ish response
	body := strings.Repeat("x", 4096)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	// Extract host:port from test server
	addr := srv.Listener.Addr().String()

	// Use test server's TLS config with its CA certificate
	snapshot, err := collectWithTLS(addr, 5*time.Second, srv.Client().Transport.(*http.Transport).TLSClientConfig)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if snapshot.Target != addr {
		t.Errorf("Target = %q, want %q", snapshot.Target, addr)
	}

	if len(snapshot.Samples) == 0 {
		t.Fatal("expected samples, got none")
	}

	var hasSent, hasRecv bool
	for _, s := range snapshot.Samples {
		if s.Direction {
			hasSent = true
		} else {
			hasRecv = true
		}
	}

	if !hasSent {
		t.Error("no sent samples recorded")
	}
	if !hasRecv {
		t.Error("no received samples recorded")
	}

	if snapshot.Duration <= 0 {
		t.Error("duration should be positive")
	}

	t.Logf("collected %d samples over %v", len(snapshot.Samples), snapshot.Duration)
}

// collectWithTLS is a test helper that uses a custom TLS config (for httptest servers).
func collectWithTLS(target string, duration time.Duration, tlsConfig *tls.Config) (*TrafficSnapshot, error) {
	var recorder *RecordingConn

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			tcpConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			cfg := tlsConfig.Clone()
			cfg.ServerName = "127.0.0.1"
			tlsConn := tls.Client(tcpConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tlsConn.Close()
				return nil, err
			}

			recorder = NewRecordingConn(tlsConn)
			return recorder, nil
		},
	}

	client := &http.Client{Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+target+"/", nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	transport.CloseIdleConnections()

	elapsed := time.Since(start)

	if recorder == nil {
		return nil, fmt.Errorf("no connection was established")
	}

	return &TrafficSnapshot{
		Samples:   recorder.Samples(),
		Target:    target,
		Duration:  elapsed,
		CreatedAt: start,
	}, nil
}
