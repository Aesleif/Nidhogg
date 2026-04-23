package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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
	idleTimeout     time.Duration
	profileVersion  atomic.Uint32
	cachedProfile   atomic.Pointer[profile.Profile]
	ProfileOverride atomic.Pointer[profile.Profile]
}

// NewDialer creates a Dialer for the given server configuration.
// fingerprint controls the TLS ClientHello: "randomized" (default), "chrome", "firefox", "safari".
// shapingMode controls traffic shaping mode applied to established tunnels.
// poolSize sets how many parallel TCP+TLS connections the HTTP/2 transport
// keeps to the server (mitigates TCP head-of-line blocking). Values <=1
// keep the default single-connection pool.
// idleTimeout closes a tunnel conn after that long without Read/Write
// activity. Zero disables the idle timer (use with care; tunnels stuck on
// silent peers will leak goroutines + h2 stream buffers indefinitely).
// connMaxAge retires pooled HTTP/2 connections older than that and
// gracefully redials replacements, preventing slow accumulation of
// internal h2 state and stale TCP path issues. Zero disables recycling.
// rootCAs overrides the system trust anchors; nil uses system roots.
// Tests supply their httptest server's cert pool here.
func NewDialer(server, tunnelPath string, psk []byte, rootCAs *x509.CertPool, fingerprint string, shapingMode shaper.ShapingMode, poolSize int, idleTimeout, connMaxAge time.Duration) *Dialer {
	helloID, _ := transport.FingerprintID(fingerprint) // validated in config

	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return transport.DialTLS(ctx, network, addr, rootCAs, helloID)
	}

	h2transport := &http2.Transport{
		// 64 KiB frame size — see server config for rationale (memory vs
		// per-frame overhead tradeoff).
		MaxReadFrameSize: 1 << 16,
		// Keepalive: without these a silently-dead server end leaks tunnel
		// streams (and their 64 KiB writeRequestBody buffers) until the
		// caller's context is cancelled. Ping after 30 s of idle read,
		// fail the connection if no pong within 15 s; fail writes stalled
		// for more than 30 s.
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 30 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return dialTLS(ctx, network, addr)
		},
	}

	// Fallback for testing with standard TLS (e.g., httptest servers that don't support uTLS)
	if helloID == (utls.ClientHelloID{}) {
		stdDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, &tls.Config{
				RootCAs:    rootCAs,
				NextProtos: []string{"h2"},
			})
		}
		h2transport = &http2.Transport{
			MaxReadFrameSize: 1 << 16,
			ReadIdleTimeout:  30 * time.Second,
			PingTimeout:      15 * time.Second,
			WriteByteTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs: rootCAs,
			},
		}
		dialTLS = stdDial
	}

	if poolSize > 1 {
		h2transport.ConnPool = NewConnPool(h2transport, poolSize, connMaxAge, dialTLS)
	}

	serverURL := "https://" + server + tunnelPath

	return &Dialer{
		serverURL:   serverURL,
		psk:         psk,
		client:      &http.Client{Transport: h2transport},
		shapingMode: shapingMode,
		idleTimeout: idleTimeout,
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

	if resp.StatusCode != http.StatusOK {
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
	// Sanity bound: real profiles are ~10–50 KB of JSON. A garbage value
	// here (e.g. from a fallback cover-site HTML body returned with 200
	// OK when the tunnel wasn't actually accepted) would otherwise trigger
	// a huge allocation. 1 MiB is well above the legitimate maximum.
	const maxProfileSize = 1 << 20
	if profSize > maxProfileSize {
		pw.Close()
		resp.Body.Close()
		return nil, nil, 0, fmt.Errorf("profile size out of range: %d", profSize)
	}
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
		prevVersion := d.profileVersion.Swap(serverVersion)
		d.cachedProfile.Store(prof)
		// Log only on version change — DialTunnel runs per-stream and
		// would otherwise emit an INFO line for every connection.
		if prevVersion != serverVersion {
			slog.Info("profile: applied",
				"version", serverVersion,
				"previous", prevVersion,
				"name", prof.Name,
				"cdf_points", len(prof.SendSizeCDF),
				"avg_burst", prof.AvgBurstLen)
		}
	} else if serverVersion != 0 {
		// Server has a profile but version matches — reuse the cached one.
		// Without this the next Dial() would return a nil profile and
		// disable client-side shaping while the server keeps shaping
		// (because clientShaping is signaled per-request, not per-profile).
		d.profileVersion.Store(serverVersion)
		prof = d.cachedProfile.Load()
	}

	var conn net.Conn = &tunnelConn{
		reader: resp.Body,
		writer: pw,
	}

	// Bound the tunnel's lifetime when no traffic flows. h2 stream itself
	// has no per-stream idle limit; without this, half-dead tunnels keep
	// their goroutines + 64 KiB scratch buffer alive indefinitely.
	conn = transport.NewIdleConn(conn, d.idleTimeout)

	activeProf := d.ProfileOverride.Load()
	if activeProf == nil {
		activeProf = prof
	}

	// UDP tunnels are framed at the application layer (length-prefixed
	// datagrams) and the server bypasses ShapedConn for them, so the
	// client must too — otherwise the framing layers collide and parse
	// each other as garbage.
	if activeProf != nil && d.shapingMode != shaper.Disabled && dd.Command != transport.CommandUDP {
		return shaper.NewShapedConn(conn, activeProf, d.shapingMode), prof, handshakeRTT, nil
	}
	return conn, prof, handshakeRTT, nil
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
