package transport

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestPeekConnPeekThenRead(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		client.Write([]byte("HELLO WORLD"))
		client.Close()
	}()

	pc := NewPeekConn(server)
	peek, err := pc.Peek(5)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	if !bytes.Equal(peek, []byte("HELLO")) {
		t.Errorf("peek = %q, want HELLO", peek)
	}

	full, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(full, []byte("HELLO WORLD")) {
		t.Errorf("read = %q, want HELLO WORLD", full)
	}
}

func TestPeekConnPeekTwice(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		client.Write([]byte("ABCDEFGHIJ"))
		client.Close()
	}()

	pc := NewPeekConn(server)
	peek1, _ := pc.Peek(3)
	if string(peek1) != "ABC" {
		t.Errorf("peek1 = %q, want ABC", peek1)
	}

	// Second Peek that extends beyond first
	peek2, err := pc.Peek(7)
	if err != nil {
		t.Fatalf("Peek 7: %v", err)
	}
	if string(peek2) != "ABCDEFG" {
		t.Errorf("peek2 = %q, want ABCDEFG", peek2)
	}
}

func TestPeekConnShortStream(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		client.Write([]byte("HI"))
		client.Close()
	}()

	pc := NewPeekConn(server)
	peek, err := pc.Peek(10)
	if err == nil {
		t.Fatalf("expected error on short peek, got nil with peek=%q", peek)
	}
	// Whatever we got back, must contain at least the bytes that arrived.
	if !bytes.Equal(peek[:2], []byte("HI")) {
		t.Errorf("peek = %q, want HI prefix", peek)
	}
}
