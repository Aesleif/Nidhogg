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

const minSamplesForSnapshot = 10

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
			handleTelemetry(w, flusher, reader, pm, agg, clientVersion)
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

		// UDP relay: frame datagrams without shaping
		if network == "udp" {
			tc := &serverTunnelConn{reader: reader, writer: w, flusher: flusher}
			udprelay.RelayUDP(r.Context(), upstream, tc)
			return
		}

		// closeUpstream fully tears down the upstream TCP socket so that
		// whichever relay goroutine is blocked on a Read from it gets
		// unstuck and exits. Without this, an idle-but-alive upstream
		// (websocket, MTProto long-poll) leaves the response goroutine
		// hung forever after the client disconnects, wedging wg.Wait()
		// and leaking the TCP socket + frame buffers.
		var closeOnce sync.Once
		closeUpstream := func() {
			closeOnce.Do(func() { tcpUpstream.Close() })
		}

		// If we have a profile AND the client signaled it will frame, wrap
		// the relay in ShapedConn (both directions). Server uses Stream mode
		// — padding only, no artificial delays.
		if activeProfile != nil && clientShaping {
			tc := &serverTunnelConn{reader: reader, writer: w, flusher: flusher}
			shaped := shaper.NewShapedConn(tc, activeProfile, shaper.Stream)

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer closeUpstream()
				io.Copy(upstream, shaped)
			}()

			go func() {
				defer wg.Done()
				defer closeUpstream()
				io.Copy(shaped, upstream)
			}()

			wg.Wait()
		} else {
			// Fallback: raw relay without shaping
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				defer closeUpstream()
				io.Copy(upstream, reader)
			}()

			go func() {
				defer wg.Done()
				defer closeUpstream()
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
type serverTunnelConn struct {
	reader  io.Reader
	writer  io.Writer
	flusher http.Flusher
}

func (c *serverTunnelConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *serverTunnelConn) Write(b []byte) (int, error) {
	n, err := c.writer.Write(b)
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *serverTunnelConn) Close() error                       { return nil }
func (c *serverTunnelConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *serverTunnelConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }
func (c *serverTunnelConn) SetDeadline(_ time.Time) error      { return nil }
func (c *serverTunnelConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *serverTunnelConn) SetWriteDeadline(_ time.Time) error { return nil }

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
func handleTelemetry(w http.ResponseWriter, flusher http.Flusher, reader io.Reader, pm *ProfileManager, agg *telemetry.Aggregator, clientVersion uint32) {
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
