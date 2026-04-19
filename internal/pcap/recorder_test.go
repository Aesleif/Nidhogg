package pcap

import (
	"net"
	"testing"
)

// TestRecordingConnCapsSamples ensures the per-connection sample slice is
// hard-capped so long-lived tunnels (websockets, large downloads) cannot
// grow it without bound.
func TestRecordingConnCapsSamples(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	rec := NewRecordingConn(server)

	go func() {
		buf := make([]byte, 8)
		for i := 0; i < maxSamples*2; i++ {
			client.Write(buf)
		}
		client.Close()
	}()

	buf := make([]byte, 8)
	for i := 0; i < maxSamples*2; i++ {
		if _, err := rec.Read(buf); err != nil {
			break
		}
	}

	if got := len(rec.Samples()); got > maxSamples {
		t.Errorf("samples = %d, want <= %d", got, maxSamples)
	}
}
