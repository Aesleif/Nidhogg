package server

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/aesleif/nidhogg/internal/transport"
)

// TunnelHandler creates an http.Handler that handles tunnel connections.
// If the PSK in the request body matches, the connection is tunneled
// to the destination specified by the client. Otherwise, the request
// is forwarded to the fallback handler (reverse proxy).
func TunnelHandler(psk []byte, fallback http.Handler, pm *ProfileManager) http.Handler {
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
			log.Printf("tunnel: handshake rejected: %v", err)
			fallback.ServeHTTP(w, r)
			return
		}

		// PSK matched — read destination address (host:port\n)
		reader := bufio.NewReader(r.Body)
		dest, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("tunnel: failed to read destination: %v", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		dest = strings.TrimSpace(dest)

		// Connect to upstream target
		upstream, err := net.Dial("tcp", dest)
		if err != nil {
			log.Printf("tunnel: failed to dial %s: %v", dest, err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		defer upstream.Close()

		// Start streaming response
		flusher, ok := w.(http.Flusher)
		if !ok {
			log.Printf("tunnel: ResponseWriter does not support Flusher")
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Nidhogg-Tunnel", "1")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Send profile inline: [size:4B big-endian] [json]
		if pm != nil {
			if prof := pm.Current(); prof != nil {
				profJSON, err := json.Marshal(prof)
				if err != nil {
					log.Printf("tunnel: failed to marshal profile: %v", err)
					profJSON = nil
				}
				if len(profJSON) > 0 {
					var sizeBuf [4]byte
					binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(profJSON)))
					w.Write(sizeBuf[:])
					w.Write(profJSON)
				} else {
					w.Write([]byte{0, 0, 0, 0})
				}
			} else {
				w.Write([]byte{0, 0, 0, 0})
			}
		} else {
			w.Write([]byte{0, 0, 0, 0})
		}
		flusher.Flush()

		var wg sync.WaitGroup
		wg.Add(2)

		// Client → Upstream (request body → upstream connection)
		go func() {
			defer wg.Done()
			io.Copy(upstream, reader)
			if tc, ok := upstream.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
		}()

		// Upstream → Client (upstream connection → response body)
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
	})
}
