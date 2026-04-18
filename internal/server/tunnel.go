package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
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

// TunnelHandler creates an http.Handler that handles tunnel connections.
// If the PSK in the request body matches, the connection is tunneled
// to the destination specified by the client. Otherwise, the request
// is forwarded to the fallback handler (reverse proxy).
func TunnelHandler(psk []byte, fallback http.Handler, pm *ProfileManager, agg *telemetry.Aggregator) http.Handler {
	validator := transport.NewValidator(psk)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			fallback.ServeHTTP(w, r)
			return
		}

		handshakeBuf := make([]byte, transport.HandshakeSize)
		if _, err := io.ReadFull(r.Body, handshakeBuf); err != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		if ok, err := validator.Validate(handshakeBuf); !ok {
			slog.Debug("tunnel: handshake rejected", "err", err)
			fallback.ServeHTTP(w, r)
			return
		}

		// PSK matched — read destination address (host:port\n)
		reader := bufio.NewReader(r.Body)
		dest, err := reader.ReadString('\n')
		if err != nil {
			slog.Warn("tunnel: failed to read destination", "err", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		dest = strings.TrimSpace(dest)

		if dest == "_telemetry" {
			handleTelemetry(w, reader, pm, agg)
			return
		}

		// Parse network prefix: "udp:host:port", "tcp:host:port", or "host:port" (default tcp)
		network := "tcp"
		if strings.HasPrefix(dest, "udp:") {
			network = "udp"
			dest = dest[4:]
		} else if strings.HasPrefix(dest, "tcp:") {
			dest = dest[4:]
		}

		// Connect to upstream target
		tcpUpstream, err := net.Dial(network, dest)
		if err != nil {
			slog.Warn("tunnel: failed to dial upstream", "dest", dest, "err", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
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

		// Start streaming response
		flusher, ok := w.(http.Flusher)
		if !ok {
			slog.Error("tunnel: ResponseWriter does not support Flusher")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Nidhogg-Tunnel", "1")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Send profile inline: [size:4B big-endian] [json]
		var activeProfile *profile.Profile
		if pm != nil {
			activeProfile = pm.Current()
		}
		if activeProfile != nil {
			profJSON, err := json.Marshal(activeProfile)
			if err != nil {
				slog.Error("tunnel: failed to marshal profile", "err", err)
				activeProfile = nil
				w.Write([]byte{0, 0, 0, 0})
			} else {
				var sizeBuf [4]byte
				binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(profJSON)))
				w.Write(sizeBuf[:])
				w.Write(profJSON)
			}
		} else {
			w.Write([]byte{0, 0, 0, 0})
		}
		flusher.Flush()

		// UDP relay: frame datagrams without shaping
		if network == "udp" {
			tc := &serverTunnelConn{reader: reader, writer: w, flusher: flusher}
			udprelay.RelayUDP(r.Context(), upstream, tc)
			return
		}

		// If we have a profile, wrap the relay in ShapedConn (both directions).
		// Server uses Stream mode — padding only, no artificial delays.
		if activeProfile != nil {
			tc := &serverTunnelConn{reader: reader, writer: w, flusher: flusher}
			shaped := shaper.NewShapedConn(tc, activeProfile, shaper.Stream)

			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				io.Copy(upstream, shaped)
				if tcpConn, ok := tcpUpstream.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			go func() {
				defer wg.Done()
				io.Copy(shaped, upstream)
			}()

			wg.Wait()
		} else {
			// Fallback: raw relay without shaping
			var wg sync.WaitGroup
			wg.Add(2)

			go func() {
				defer wg.Done()
				io.Copy(upstream, reader)
				if tc, ok := tcpUpstream.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
			}()

			go func() {
				defer wg.Done()
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

func handleTelemetry(w http.ResponseWriter, reader io.Reader, pm *ProfileManager, agg *telemetry.Aggregator) {
	var report telemetry.Report
	if err := json.NewDecoder(reader).Decode(&report); err != nil {
		slog.Warn("tunnel: invalid telemetry", "err", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	slog.Debug("telemetry received", "profile", report.Profile, "status", report.Status, "rtt", report.AvgRTTMs)

	if agg != nil {
		agg.Record(report)
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Nidhogg-Tunnel", "1")
	w.WriteHeader(http.StatusOK)

	var activeProfile *profile.Profile
	if pm != nil {
		activeProfile = pm.Current()
	}
	if activeProfile != nil {
		profJSON, err := json.Marshal(activeProfile)
		if err != nil {
			w.Write([]byte{0, 0, 0, 0})
			flusher.Flush()
			return
		}
		var sizeBuf [4]byte
		binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(profJSON)))
		w.Write(sizeBuf[:])
		w.Write(profJSON)
	} else {
		w.Write([]byte{0, 0, 0, 0})
	}
	flusher.Flush()
}
