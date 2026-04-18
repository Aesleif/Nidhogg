package udprelay

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestWriteReadPacket(t *testing.T) {
	var buf bytes.Buffer
	data := []byte("hello UDP")

	if err := WritePacket(&buf, data); err != nil {
		t.Fatal(err)
	}

	// Check wire format: 2-byte big-endian length + payload
	raw := buf.Bytes()
	if len(raw) != 2+len(data) {
		t.Fatalf("expected %d bytes on wire, got %d", 2+len(data), len(raw))
	}
	if raw[0] != 0 || raw[1] != byte(len(data)) {
		t.Fatalf("unexpected length header: %x %x", raw[0], raw[1])
	}

	got, err := ReadPacket(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %q, want %q", got, data)
	}
}

func TestMultiplePackets(t *testing.T) {
	var buf bytes.Buffer
	packets := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third with more data here"),
	}

	for _, p := range packets {
		if err := WritePacket(&buf, p); err != nil {
			t.Fatal(err)
		}
	}

	for i, want := range packets {
		got, err := ReadPacket(&buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("packet %d: got %q, want %q", i, got, want)
		}
	}
}

func TestReadPacketEOF(t *testing.T) {
	var buf bytes.Buffer
	_, err := ReadPacket(&buf)
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestWritePacketTooLarge(t *testing.T) {
	var buf bytes.Buffer
	data := make([]byte, maxDatagramSize+1)
	err := WritePacket(&buf, data)
	if err == nil {
		t.Fatal("expected error for oversized datagram")
	}
}

func TestPacketFrameConn(t *testing.T) {
	// Create a pipe to simulate a streaming connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	pfc := NewPacketFrameConn(client)

	// Write from PacketFrameConn, read raw from server
	go func() {
		pfc.Write([]byte("hello"))
	}()

	// Read raw: should see 2-byte header + "hello"
	raw := make([]byte, 7)
	if _, err := io.ReadFull(server, raw); err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0 || raw[1] != 5 {
		t.Fatalf("unexpected header: %x %x", raw[0], raw[1])
	}
	if string(raw[2:]) != "hello" {
		t.Fatalf("unexpected payload: %q", raw[2:])
	}

	// Write raw framed packet to server, read from PacketFrameConn
	go func() {
		WritePacket(server, []byte("world"))
	}()

	buf := make([]byte, 1024)
	n, err := pfc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("got %q, want %q", buf[:n], "world")
	}
}

func TestRelayUDP(t *testing.T) {
	// Create a real UDP echo server
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()

	// Echo server
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpLn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpLn.WriteToUDP(buf[:n], addr)
		}
	}()

	// Connect a UDP client to the echo server
	udpConn, err := net.Dial("udp", udpLn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	// Create a pipe to simulate the tunnel stream
	streamServer, streamClient := net.Pipe()
	defer streamServer.Close()
	defer streamClient.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start relay
	go RelayUDP(ctx, udpConn, streamServer)

	// Send a framed packet through the tunnel → relay → UDP echo → relay → framed response
	testData := []byte("test datagram")
	if err := WritePacket(streamClient, testData); err != nil {
		t.Fatal(err)
	}

	// Read the echoed response
	resp, err := ReadPacket(streamClient)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(resp, testData) {
		t.Fatalf("got %q, want %q", resp, testData)
	}
}
