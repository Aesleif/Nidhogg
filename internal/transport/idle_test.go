package transport

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestIdleConnClosesAfterTimeout(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	ic := NewIdleConn(server, 100*time.Millisecond)

	// No activity. Wait past the timeout, then a Read must return error.
	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 16)
	_, err := ic.Read(buf)
	if err == nil {
		t.Fatal("expected error after idle timeout, got nil")
	}
	if !errors.Is(err, io.ErrClosedPipe) && err.Error() != "io: read/write on closed pipe" {
		t.Logf("got error: %v (acceptable — any non-nil works)", err)
	}
}

func TestIdleConnResetsOnActivity(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	// Drain whatever client sends so Write doesn't block.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()

	ic := NewIdleConn(server, 100*time.Millisecond)

	// Write every 30ms for ~250ms — well past timeout, but each Write
	// resets the deadline. Conn must still be alive at the end.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := ic.Write([]byte("x")); err != nil {
			t.Fatalf("Write failed mid-loop: %v", err)
		}
		time.Sleep(30 * time.Millisecond)
	}

	if _, err := ic.Write([]byte("final")); err != nil {
		t.Fatalf("Write after activity loop: %v", err)
	}

	// Now stop activity, wait past timeout, must close.
	time.Sleep(200 * time.Millisecond)
	buf := make([]byte, 16)
	if _, err := ic.Read(buf); err == nil {
		t.Fatal("expected error after final idle, got nil")
	}
}

func TestIdleConnCloseStopsTimer(t *testing.T) {
	server, _ := net.Pipe()
	ic := NewIdleConn(server, 100*time.Millisecond).(*IdleConn)

	if err := ic.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Sleep past timeout to ensure no panic from a fired timer touching
	// already-closed conn (race detector should flag any issue).
	time.Sleep(200 * time.Millisecond)
}

func TestIdleConnZeroTimeoutIsBare(t *testing.T) {
	server, _ := net.Pipe()
	defer server.Close()

	c := NewIdleConn(server, 0)
	if _, ok := c.(*IdleConn); ok {
		t.Fatal("zero timeout must return bare conn, got IdleConn wrapper")
	}
}
