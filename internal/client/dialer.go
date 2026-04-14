package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// Dialer manages HTTP/2 connections to a nidhogg server and creates
// tunnel streams. A single Dialer multiplexes all tunnels over one
// TLS connection via HTTP/2 streams.
type Dialer struct {
	serverURL string
	psk       []byte
	client    *http.Client
}

// NewDialer creates a Dialer for the given server configuration.
func NewDialer(server, tunnelPath string, psk []byte, insecure bool) *Dialer {
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	serverURL := "https://" + server + tunnelPath

	return &Dialer{
		serverURL: serverURL,
		psk:       psk,
		client:    &http.Client{Transport: transport},
	}
}

// DialTunnel opens a new tunnel stream to the given destination (host:port)
// through the nidhogg server. The returned net.Conn represents the
// bidirectional tunnel.
func (d *Dialer) DialTunnel(ctx context.Context, dest string) (net.Conn, error) {
	pr, pw := io.Pipe()

	// Write PSK and destination before HTTP request is sent.
	// This must happen in a goroutine because pw.Write blocks
	// until the HTTP client reads from pr.
	headerWritten := make(chan error, 1)
	go func() {
		if _, err := pw.Write(d.psk); err != nil {
			headerWritten <- fmt.Errorf("write PSK: %w", err)
			return
		}
		if _, err := pw.Write([]byte(dest + "\n")); err != nil {
			headerWritten <- fmt.Errorf("write destination: %w", err)
			return
		}
		headerWritten <- nil
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.serverURL, pr)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := d.client.Do(req)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Check if header write succeeded
	if writeErr := <-headerWritten; writeErr != nil {
		resp.Body.Close()
		pw.Close()
		return nil, writeErr
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("tunnel rejected (status %d): %s", resp.StatusCode, string(body))
	}

	return &tunnelConn{
		reader: resp.Body,
		writer: pw,
	}, nil
}

// tunnelConn adapts an HTTP/2 streaming response into a net.Conn.
type tunnelConn struct {
	reader io.ReadCloser  // resp.Body — server→client
	writer io.WriteCloser // pipe writer — client→server
}

func (c *tunnelConn) Read(b []byte) (int, error)  { return c.reader.Read(b) }
func (c *tunnelConn) Write(b []byte) (int, error) { return c.writer.Write(b) }

func (c *tunnelConn) Close() error {
	wErr := c.writer.Close()
	rErr := c.reader.Close()
	if wErr != nil {
		return wErr
	}
	return rErr
}

func (c *tunnelConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *tunnelConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *tunnelConn) SetDeadline(_ time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(_ time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tunnel" }
func (dummyAddr) String() string  { return "tunnel" }
