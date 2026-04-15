package pcap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Collect opens an HTTPS connection to target, sends a GET request,
// and records all read/write sizes on the underlying TLS connection.
func Collect(target string, duration time.Duration) (*TrafficSnapshot, error) {
	var recorder *RecordingConn

	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			tcpConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, fmt.Errorf("tcp dial: %w", err)
			}

			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("split host port: %w", err)
			}

			tlsConn := tls.Client(tcpConn, &tls.Config{
				ServerName: host,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				tlsConn.Close()
				return nil, fmt.Errorf("tls handshake: %w", err)
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
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
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
