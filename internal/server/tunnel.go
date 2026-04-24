package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
	"github.com/aesleif/nidhogg/internal/shaper"
	"github.com/aesleif/nidhogg/internal/telemetry"
	"github.com/aesleif/nidhogg/internal/transport"
	"github.com/aesleif/nidhogg/internal/udprelay"
)

const (
	minSamplesForSnapshot = 10
	// telemetryReadTimeout bounds the tunnel body read during a
	// CommandTelemetry request. An authenticated client that never
	// finishes sending its JSON report used to hold the stream open
	// indefinitely, leaking the h2 stream + goroutine.
	telemetryReadTimeout = 15 * time.Second
)

// TunnelHandler creates an http.Handler that runs the Ed25519
// challenge-response handshake and tunnels authenticated clients.
// Unknown clients (bad version byte, unauthorized pubkey) are forwarded
// to the fallback handler (reverse proxy to the cover site) so probes
// see only cover-site traffic.
// acl screens client-supplied destinations before dial; production
// passes DefaultDestACL{} to block loopback/private/CGNAT/link-local/
// multicast ranges. Tests pass NopDestChecker{}.
func TunnelHandler(auth *transport.AuthStore, acl DestChecker, fallback http.Handler, pm *ProfileManager, agg *telemetry.Aggregator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fallback.ServeHTTP(w, r)
			return
		}

		// 1. Client hello: [version:1][pubkey:32].
		helloBuf := make([]byte, transport.HelloSize)
		if _, err := io.ReadFull(r.Body, helloBuf); err != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		pub, err := transport.ParseHello(helloBuf)
		if err != nil || !auth.Has(pub) {
			fallback.ServeHTTP(w, r)
			return
		}

		// 2. We've committed to the protocol. Issue challenge and
		//    verify the client's signature before reading anything else.
		flusher, flusherOK := w.(http.Flusher)
		if !flusherOK {
			slog.Error("tunnel: ResponseWriter does not support Flusher")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		// rc drives in-flight r.Body.Read / Write cancellation via
		// SetReadDeadline / SetWriteDeadline. Used by closeBoth (below)
		// to unblock whichever relay direction is still reading from the
		// tunnel when its sibling exits — otherwise a silent client +
		// dead upstream leaves the handler's Read pinned forever.
		rc := http.NewResponseController(w)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		nonce, err := transport.GenerateNonce()
		if err != nil {
			return
		}
		if _, err := w.Write(nonce[:]); err != nil {
			return
		}
		flusher.Flush()

		sigBuf := make([]byte, transport.SignatureSize)
		if _, err := io.ReadFull(r.Body, sigBuf); err != nil {
			return
		}
		if !transport.VerifyChallenge(pub, nonce, sigBuf) {
			slog.Debug("tunnel: bad signature", "client", auth.Name(pub))
			return
		}

		// 3. Authenticated — read binary destination header.
		reader := bufio.NewReader(r.Body)
		d, err := transport.ReadDest(reader)
		if err != nil {
			slog.Warn("tunnel: failed to read destination", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Read client's known profile version
		var clientVersionBuf [4]byte
		if _, err := io.ReadFull(reader, clientVersionBuf[:]); err != nil {
			slog.Warn("tunnel: failed to read profile version", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		clientVersion := binary.BigEndian.Uint32(clientVersionBuf[:])

		// Read client's shaping mode so we only frame the relay when the
		// client also frames. Mismatched framing corrupts the entire stream.
		var shapingBuf [1]byte
		if _, err := io.ReadFull(reader, shapingBuf[:]); err != nil {
			slog.Warn("tunnel: failed to read shaping mode", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		clientShaping := shaper.DecodeMode(shapingBuf[0]) != shaper.Disabled

		if d.Command == transport.CommandTelemetry {
			handleTelemetry(w, flusher, rc, reader, pm, agg, clientVersion)
			return
		}

		dest := d.Addr()
		network := d.Network()

		// Telemetry command is in-band authentication, no external dial.
		// For tunnel commands, screen the destination before Dial. Resolve
		// once here and Dial by the returned IP literal so DNS rebinding
		// between check and Dial can't smuggle a private answer past ACL.
		allowedIP, err := acl.ResolveAndCheck(r.Context(), d.Host)
		if err != nil {
			slog.Warn("tunnel: destination rejected", "host", d.Host, "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		dialAddr := net.JoinHostPort(allowedIP.String(), strconv.Itoa(int(d.Port)))

		// Connect to upstream target. Wrap in IdleConn so half-dead
		// tunnels (silent peer + silent source) get force-closed instead
		// of leaking goroutines and h2 stream buffers indefinitely.
		// The closeOnce relay fix only fires when ONE side exits — idle
		// timeout covers the case where BOTH sides are blocked on Read.
		dialedUpstream, err := net.Dial(network, dialAddr)
		if err != nil {
			slog.Warn("tunnel: failed to dial upstream", "dest", dest, "err", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		tcpUpstream := transport.NewIdleConn(dialedUpstream, 5*time.Minute)
		defer tcpUpstream.Close()

		startTime := time.Now()

		// Wrap upstream in RecordingConn if dest matches a profile target
		var recorder *pcap.RecordingConn
		var recordTarget string
		upstream := net.Conn(tcpUpstream)
		if pm != nil {
			if t, ok := pm.MatchTarget(dest); ok {
				recorder = pcap.NewRecordingConn(tcpUpstream)
				recordTarget = t
				upstream = recorder
			}
		}

		// Response headers + challenge nonce were already sent above.
		// Continue streaming the inline profile: [version:4B] [size:4B] [json?].
		activeProfile, _ := writeProfileResponse(w, pm, clientVersion)
		flusher.Flush()

		tc := &serverTunnelConn{reader: reader, writer: w, flusher: flusher, rc: rc}

		// closeBoth tears down the upstream TCP socket AND the tunnel
		// (via rc.SetReadDeadline) so whichever relay direction is still
		// blocked on a Read — upstream OR tunnel body — gets unstuck and
		// exits. Before this was symmetric, closing only the upstream
		// left `io.Copy(upstream, shaped)` pinned in r.Body.Read forever
		// whenever the upstream was the first to EOF and the client was
		// temporarily silent (websocket idle / MTProto long-poll).
		var closeOnce sync.Once
		closeBoth := func() {
			closeOnce.Do(func() {
				tcpUpstream.Close()
				tc.Close() // SetReadDeadline(now) on the h2 request body
			})
		}

		// UDP relay: frame datagrams without shaping. RelayUDP's own
		// ctx.Done watchdog closes udpConn; closeBoth after return closes
		// the tunnel side so the stream-reading goroutine also unblocks.
		if network == "udp" {
			defer closeBoth()
			udprelay.RelayUDP(r.Context(), upstream, tc)
			return
		}

		// If we have a profile AND the client signaled it will frame, wrap
		// the relay in ShapedConn (both directions). Server uses Stream mode
		// — padding only, no artificial delays.
		if activeProfile != nil && clientShaping {
			shaped := shaper.NewShapedConn(tc, activeProfile, shaper.Stream)

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer closeBoth()
				io.Copy(upstream, shaped)
			}()

			go func() {
				defer wg.Done()
				defer closeBoth()
				io.Copy(shaped, upstream)
			}()

			wg.Wait()
		} else {
			// Fallback: raw relay without shaping
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer closeBoth()
				io.Copy(upstream, reader)
			}()

			go func() {
				defer wg.Done()
				defer closeBoth()
				buf := make([]byte, 32*1024)
				for {
					n, readErr := upstream.Read(buf)
					if n > 0 {
						if _, writeErr := w.Write(buf[:n]); writeErr != nil {
							return
						}
						flusher.Flush()
					}
					if readErr != nil {
						return
					}
				}
			}()

			wg.Wait()
		}

		// After relay: feed recorded snapshot to ProfileManager
		if recorder != nil {
			samples := recorder.Samples()
			if len(samples) >= minSamplesForSnapshot {
				pm.Record(recordTarget, &pcap.TrafficSnapshot{
					Samples:   samples,
					Target:    recordTarget,
					Duration:  time.Since(startTime),
					CreatedAt: startTime,
				})
			}
		}
	})
}

// serverTunnelConn adapts (reader, ResponseWriter) to net.Conn
// so ShapedConn can wrap the server side of the tunnel.
//
// Close / SetReadDeadline / SetWriteDeadline delegate to the
// http.ResponseController so callers can force-unblock an in-flight
// r.Body.Read or w.Write on the h2 stream.
type serverTunnelConn struct {
	reader  io.Reader
	writer  io.Writer
	flusher http.Flusher
	rc      *http.ResponseController

	closeOnce sync.Once
	closeErr  error
}

func (c *serverTunnelConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *serverTunnelConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

// Close drops any in-flight read/write on the tunnel body by pushing
// both deadlines to now. Idempotent.
func (c *serverTunnelConn) Close() error {
	c.closeOnce.Do(func() {
		if c.rc == nil {
			return
		}
		now := time.Now()
		if err := c.rc.SetReadDeadline(now); err != nil {
			c.closeErr = err
		}
		// Best-effort on the write side: if a Write is pinned on h2 flow
		// control we want to unblock it too; record only the read-side
		// error if both fail.
		_ = c.rc.SetWriteDeadline(now)
	})
	return c.closeErr
}

func (c *serverTunnelConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *serverTunnelConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

func (c *serverTunnelConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *serverTunnelConn) SetReadDeadline(t time.Time) error {
	if c.rc == nil {
		return nil
	}
	return c.rc.SetReadDeadline(t)
}

func (c *serverTunnelConn) SetWriteDeadline(t time.Time) error {
	if c.rc == nil {
		return nil
	}
	return c.rc.SetWriteDeadline(t)
}

// writeProfileResponse writes [version:4B][size:4B][json?] to w.
// If clientVersion matches the current profile, size=0 and json is omitted.
// Returns the active profile (if any) and the version sent.
func writeProfileResponse(w io.Writer, pm *ProfileManager, clientVersion uint32) (*profile.Profile, uint32) {
	var activeProfile *profile.Profile
	if pm != nil {
		activeProfile = pm.Current()
	}

	var versionBuf [4]byte
	if activeProfile == nil {
		// No profile: version=0, size=0
		w.Write(versionBuf[:]) // version = 0
		w.Write(versionBuf[:]) // size = 0
		return nil, 0
	}

	profJSON, err := json.Marshal(activeProfile)
	if err != nil {
		slog.Error("tunnel: failed to marshal profile", "err", err)
		w.Write(versionBuf[:]) // version = 0
		w.Write(versionBuf[:]) // size = 0
		return nil, 0
	}

	version := profile.VersionHash(profJSON)
	binary.BigEndian.PutUint32(versionBuf[:], version)
	w.Write(versionBuf[:])

	if clientVersion == version {
		// Client already has this version — skip JSON
		w.Write([]byte{0, 0, 0, 0})
		return activeProfile, version
	}

	var sizeBuf [4]byte
	binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(profJSON)))
	w.Write(sizeBuf[:])
	w.Write(profJSON)
	return activeProfile, version
}

// handleTelemetry is invoked after the full challenge-response, so the
// response headers and the authentication nonce have already been sent.
// It just reads the client's JSON report, forwards it to the aggregator,
// and appends the inline profile payload.
//
// The tunnel body read is bounded by telemetryReadTimeout so a slow /
// malicious authenticated client cannot hold the h2 stream open forever
// mid-Decode.
func handleTelemetry(w http.ResponseWriter, flusher http.Flusher, rc *http.ResponseController, reader io.Reader, pm *ProfileManager, agg *telemetry.Aggregator, clientVersion uint32) {
	if rc != nil {
		_ = rc.SetReadDeadline(time.Now().Add(telemetryReadTimeout))
		defer func() { _ = rc.SetReadDeadline(time.Time{}) }()
	}
	var report telemetry.Report
	if err := json.NewDecoder(reader).Decode(&report); err != nil {
		slog.Warn("tunnel: invalid telemetry", "err", err)
		return
	}

	slog.Debug("telemetry received", "profile", report.Profile, "status", report.Status, "rtt", report.AvgRTTMs)

	if agg != nil {
		agg.Record(report)
	}

	writeProfileResponse(w, pm, clientVersion)
	flusher.Flush()
}
