package shaper

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aesleif/nidhogg/internal/pcap"
	"github.com/aesleif/nidhogg/internal/profile"
)

// testProfile creates a simple profile for testing.
func testProfile() *profile.Profile {
	base := time.Now()
	snap := &pcap.TrafficSnapshot{
		Target:    "test",
		Duration:  time.Second,
		CreatedAt: base,
		Samples: []pcap.PacketSample{
			{Size: 100, Direction: true, Timestamp: base},
			{Size: 200, Direction: false, Timestamp: base.Add(10 * time.Millisecond)},
			{Size: 150, Direction: true, Timestamp: base.Add(20 * time.Millisecond)},
			{Size: 300, Direction: false, Timestamp: base.Add(30 * time.Millisecond)},
			{Size: 500, Direction: true, Timestamp: base.Add(40 * time.Millisecond)},
			{Size: 1000, Direction: false, Timestamp: base.Add(50 * time.Millisecond)},
		},
	}
	return profile.Generate("test", []*pcap.TrafficSnapshot{snap})
}

func TestFrameRoundtrip(t *testing.T) {
	prof := testProfile()
	serverConn, clientConn := net.Pipe()

	shaped1 := NewShapedConn(clientConn, prof, Stream)
	shaped2 := NewShapedConn(serverConn, prof, Stream)

	msg := []byte("hello shaped world")

	var wg sync.WaitGroup
	wg.Add(1)

	var readErr error
	var received []byte

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		n, err := shaped2.Read(buf)
		readErr = err
		received = buf[:n]
	}()

	if _, err := shaped1.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	wg.Wait()

	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if !bytes.Equal(received, msg) {
		t.Errorf("got %q, want %q", received, msg)
	}

	shaped1.Close()
	shaped2.Close()
}

func TestLargePayloadSplit(t *testing.T) {
	prof := testProfile()
	serverConn, clientConn := net.Pipe()

	shaped1 := NewShapedConn(clientConn, prof, Stream)
	shaped2 := NewShapedConn(serverConn, prof, Stream)

	// Create a payload much larger than any profile sample size
	msg := bytes.Repeat([]byte("A"), 10000)

	var wg sync.WaitGroup
	wg.Add(1)

	var readErr error
	var received bytes.Buffer

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for received.Len() < len(msg) {
			n, err := shaped2.Read(buf)
			if n > 0 {
				received.Write(buf[:n])
			}
			if err != nil {
				readErr = err
				return
			}
		}
	}()

	if _, err := shaped1.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	wg.Wait()

	if readErr != nil {
		t.Fatalf("Read: %v", readErr)
	}
	if !bytes.Equal(received.Bytes(), msg) {
		t.Errorf("data mismatch: got %d bytes, want %d", received.Len(), len(msg))
	}

	shaped1.Close()
	shaped2.Close()
}

func TestPaddingSize(t *testing.T) {
	prof := testProfile()

	// Use raw pipe: write shaped frames on one side, read raw bytes on the other
	rawServer, clientConn := net.Pipe()

	shaped := NewShapedConn(clientConn, prof, Stream)

	msg := []byte("hi")

	var wg sync.WaitGroup
	wg.Add(1)

	var rawBytes []byte

	go func() {
		defer wg.Done()
		buf := make([]byte, 65536)
		n, _ := rawServer.Read(buf)
		rawBytes = buf[:n]
	}()

	if _, err := shaped.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	wg.Wait()

	// Frame should be at least frameOverhead + len(msg)
	if len(rawBytes) < frameOverhead+len(msg) {
		t.Errorf("raw frame too small: %d bytes", len(rawBytes))
	}

	// Frame should have padding (larger than minimum needed)
	minSize := frameOverhead + len(msg)
	if len(rawBytes) <= minSize {
		t.Logf("no padding added (frame=%d, min=%d) — profile may have sampled small size", len(rawBytes), minSize)
	} else {
		t.Logf("padding added: frame=%d, payload=%d, overhead=%d, padding=%d",
			len(rawBytes), len(msg), frameOverhead, len(rawBytes)-minSize)
	}

	shaped.Close()
	rawServer.Close()
}

func TestAllModes(t *testing.T) {
	modes := []struct {
		name string
		mode ShapingMode
	}{
		{"Stream", Stream},
		{"Balanced", Balanced},
		{"Stealth", Stealth},
	}

	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			prof := testProfile()
			serverConn, clientConn := net.Pipe()

			shaped1 := NewShapedConn(clientConn, prof, m.mode)
			shaped2 := NewShapedConn(serverConn, prof, m.mode)

			msg := []byte("test mode " + m.name)

			var wg sync.WaitGroup
			wg.Add(1)

			var received []byte

			go func() {
				defer wg.Done()
				buf := make([]byte, 1024)
				n, _ := shaped2.Read(buf)
				received = buf[:n]
			}()

			shaped1.Write(msg)
			wg.Wait()

			if !bytes.Equal(received, msg) {
				t.Errorf("got %q, want %q", received, msg)
			}

			shaped1.Close()
			shaped2.Close()
		})
	}
}

func TestMultipleMessages(t *testing.T) {
	prof := testProfile()
	serverConn, clientConn := net.Pipe()

	shaped1 := NewShapedConn(clientConn, prof, Stream)
	shaped2 := NewShapedConn(serverConn, prof, Stream)

	messages := []string{"first", "second", "third message longer"}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for _, msg := range messages {
			buf := make([]byte, 1024)
			n, err := shaped2.Read(buf)
			if err != nil {
				t.Errorf("Read: %v", err)
				return
			}
			if string(buf[:n]) != msg {
				t.Errorf("got %q, want %q", buf[:n], msg)
			}
		}
	}()

	for _, msg := range messages {
		if _, err := shaped1.Write([]byte(msg)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	wg.Wait()

	shaped1.Close()
	shaped2.Close()
}

func TestBidirectional(t *testing.T) {
	prof := testProfile()
	serverConn, clientConn := net.Pipe()

	client := NewShapedConn(clientConn, prof, Stream)
	server := NewShapedConn(serverConn, prof, Stream)

	// Echo: server reads and writes back
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if err != nil {
				return
			}
			server.Write(buf[:n])
		}
	}()

	msg := []byte("echo test data")
	client.Write(msg)

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("Read echo: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("echo = %q, want %q", buf[:n], msg)
	}

	_ = io.Closer(client)
	client.Close()
	server.Close()
}
