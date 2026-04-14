package client

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestTunnelConn_ReadWrite(t *testing.T) {
	// Simulate server→client with a buffer
	serverData := io.NopCloser(bytes.NewReader([]byte("from server")))

	// Simulate client→server with a pipe
	pr, pw := io.Pipe()

	conn := &tunnelConn{
		reader: serverData,
		writer: pw,
	}

	// Test Write
	go func() {
		conn.Write([]byte("from client"))
		conn.Close()
	}()

	written, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if string(written) != "from client" {
		t.Errorf("written = %q, want %q", string(written), "from client")
	}

	// Test Read
	buf := make([]byte, 20)
	// reader was already consumed above, create a new conn for read test
	conn2 := &tunnelConn{
		reader: io.NopCloser(bytes.NewReader([]byte("hello"))),
		writer: pw,
	}
	n, _ := conn2.Read(buf)
	if string(buf[:n]) != "hello" {
		t.Errorf("read = %q, want %q", string(buf[:n]), "hello")
	}
}

func TestTunnelConn_ImplementsNetConn(t *testing.T) {
	var _ net.Conn = (*tunnelConn)(nil)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestTunnelConn_Deadlines(t *testing.T) {
	conn := &tunnelConn{
		reader: io.NopCloser(bytes.NewReader(nil)),
		writer: nopWriteCloser{io.Discard},
	}

	// Deadline methods should be no-ops (return nil)
	if err := conn.SetDeadline(time.Now()); err != nil {
		t.Errorf("SetDeadline returned error: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		t.Errorf("SetReadDeadline returned error: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Errorf("SetWriteDeadline returned error: %v", err)
	}
}

func TestDummyAddr(t *testing.T) {
	addr := dummyAddr{}
	if addr.Network() != "tunnel" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "tunnel")
	}
	if addr.String() != "tunnel" {
		t.Errorf("String() = %q, want %q", addr.String(), "tunnel")
	}
}
