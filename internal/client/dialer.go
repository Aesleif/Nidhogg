package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/transport"
)

// Dialer manages HTTP/2 connections to a nidhogg server and creates
// tunnel streams. A single Dialer multiplexes all tunnels over one
// TLS connection via HTTP/2 streams.
type Dialer struct {
	serverURL       string
	psk             []byte
	client          *http.Client
	shapingMode     shaper.ShapingMode
	profileVersion  atomic.Uint32
	ProfileOverride atomic.Pointer[profile.Profile]
}

// NewDialer creates a Dialer for the given server configuration.
// fingerprint controls the TLS ClientHello: "randomized" (default), "chrome", "firefox", "safari".
// shapingMode controls traffic shaping mode applied to established tunnels.
func NewDialer(server, tunnelPath string, psk []byte, insecure bool, fingerprint string, shapingMode shaper.ShapingMode) *Dialer {
	helloID, _ := transport.FingerprintID(fingerprint) // validated in config

	h2transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return transport.DialTLS(ctx, network, addr, insecure, helloID)
		},
	}

	// Fallback for testing with standard TLS (e.g., httptest servers that don't support uTLS)
	if helloID == (utls.ClientHelloID{}) {
		h2transport = &http2.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		}
	}

	serverURL := "https://" + server + tunnelPath

	return &Dialer{
		serverURL:   serverURL,
		psk:         psk,
		client:      &http.Client{Transport: h2transport},
		shapingMode: shapingMode,
	}
}

func (d *Dialer) Client() *http.Client { return d.client }
func (d *Dialer) ServerURL() string    { return d.serverURL }

// DialTunnel opens a new tunnel stream to the given destination (host:port)
// through the nidhogg server. The returned net.Conn represents the
// bidirectional tunnel. handshakeRTT is the time from request to 200 OK.
func (d *Dialer) DialTunnel(ctx context.Context, dest string) (net.Conn, *profile.Profile, time.Duration, error) {
	// Build header synchronously: handshake + destination
	var header bytes.Buffer
	marker, err := transport.GenerateHandshake(d.psk)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("generate handshake: %w", err)
	}
	header.Write(marker)
	dd, err := transport.ParseDestination(dest)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("parse destination: %w", err)
	}
	if err := transport.WriteDest(&header, dd); err != nil {
		return nil, nil, 0, fmt.Errorf("write destination: %w", err)
	}
	// Write known profile version so server can skip unchanged profiles
	var knownVersionBuf [4]byte
	binary.BigEndian.PutUint32(knownVersionBuf[:], d.profileVersion.Load())
	header.Write(knownVersionBuf[:])

	// Signal client's shaping mode so the server only wraps the relay
	// in a ShapedConn when the client also will. Otherwise the framing
	// would mismatch and corrupt all data.
	header.WriteByte(shaper.EncodeMode(d.shapingMode))

	pr, pw := io.Pipe()
	body := io.MultiReader(&header, pr)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.serverURL, body)
	if err != nil {
		pw.Close()
		return nil, nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	dialStart := time.Now()
	resp, err := d.client.Do(req)
	if err != nil {
		pw.Close()
		return nil, nil, 0, fmt.Errorf("request failed: %w", err)
	}
	handshakeRTT := time.Since(dialStart)

	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Nidhogg-Tunnel") != "1" {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		pw.Close()
		resp.Body.Close()
		return nil, nil, 0, fmt.Errorf("tunnel rejected (status %d): %s", resp.StatusCode, string(body))
	}

	// Read inline profile: [version:4B] [size:4B] [json?]
	var prof *profile.Profile
	var versionBuf [4]byte
	if _, err := io.ReadFull(resp.Body, versionBuf[:]); err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, nil, 0, fmt.Errorf("read profile version: %w", err)
	}
	serverVersion := binary.BigEndian.Uint32(versionBuf[:])

	var sizeBuf [4]byte
	if _, err := io.ReadFull(resp.Body, sizeBuf[:]); err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, nil, 0, fmt.Errorf("read profile size: %w", err)
	}
	profSize := binary.BigEndian.Uint32(sizeBuf[:])
	if profSize > 0 {
		profJSON := make([]byte, profSize)
		if _, err := io.ReadFull(resp.Body, profJSON); err != nil {
			pw.Close()
			resp.Body.Close()
			return nil, nil, 0, fmt.Errorf("read profile data: %w", err)
		}
		prof = &profile.Profile{}
		if err := json.Unmarshal(profJSON, prof); err != nil {
			pw.Close()
			resp.Body.Close()
			return nil, nil, 0, fmt.Errorf("parse profile: %w", err)
		}
		d.profileVersion.Store(serverVersion)
	} else if serverVersion != 0 {
		// Server has a profile but version matches — we already have it
		d.profileVersion.Store(serverVersion)
	}

	baseConn := &tunnelConn{
		reader: resp.Body,
		writer: pw,
	}

	activeProf := d.ProfileOverride.Load()
	if activeProf == nil {
		activeProf = prof
	}

	if activeProf != nil && d.shapingMode != shaper.Disabled {
		return shaper.NewShapedConn(baseConn, activeProf, d.shapingMode), prof, handshakeRTT, nil
	}
	return baseConn, prof, handshakeRTT, nil
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

func (c *tunnelConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *tunnelConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *tunnelConn) SetDeadline(_ time.Time) error      { return nil }
func (c *tunnelConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *tunnelConn) SetWriteDeadline(_ time.Time) error { return nil }
