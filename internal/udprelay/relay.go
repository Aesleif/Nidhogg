package udprelay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const maxDatagramSize = 65535

// WritePacket writes a UDP datagram into a stream with a 2-byte big-endian length prefix.
func WritePacket(w io.Writer, data []byte) error {
	if len(data) > maxDatagramSize {
		return fmt.Errorf("datagram too large: %d > %d", len(data), maxDatagramSize)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadPacket reads one length-prefixed UDP datagram from a stream.
func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(hdr[:])
	if size == 0 {
		return nil, fmt.Errorf("zero-length datagram")
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RelayUDP copies datagrams between a UDP net.Conn and a framed TCP stream.
// It blocks until ctx is cancelled or an error occurs.
func RelayUDP(ctx context.Context, udpConn net.Conn, stream io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once
	setErr := func(err error) {
		errOnce.Do(func() { firstErr = err })
		cancel()
	}

	// stream → udpConn: read framed packets, write to UDP
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			data, err := ReadPacket(stream)
			if err != nil {
				setErr(err)
				return
			}
			if _, err := udpConn.Write(data); err != nil {
				setErr(err)
				return
			}
		}
	}()

	// udpConn → stream: read UDP datagrams, write framed to stream
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, maxDatagramSize)
		for {
			n, err := udpConn.Read(buf)
			if err != nil {
				setErr(err)
				return
			}
			if err := WritePacket(stream, buf[:n]); err != nil {
				setErr(err)
				return
			}
		}
	}()

	// Wait for context cancellation to close connections
	go func() {
		<-ctx.Done()
		udpConn.Close()
	}()

	wg.Wait()
	return firstErr
}

// PacketFrameConn wraps a streaming net.Conn to provide datagram framing.
// Each Write is prefixed with a 2-byte length header.
// Each Read returns exactly one datagram (reading the length header first).
// This is used by the SOCKS5 UDP ASSOCIATE handler where go-socks5
// calls Write(datagram) / Read(buf) per UDP packet.
type PacketFrameConn struct {
	inner net.Conn
}

// NewPacketFrameConn wraps a streaming connection with packet framing.
func NewPacketFrameConn(conn net.Conn) *PacketFrameConn {
	return &PacketFrameConn{inner: conn}
}

func (c *PacketFrameConn) Write(b []byte) (int, error) {
	if err := WritePacket(c.inner, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *PacketFrameConn) Read(b []byte) (int, error) {
	data, err := ReadPacket(c.inner)
	if err != nil {
		return 0, err
	}
	if len(data) > len(b) {
		return 0, fmt.Errorf("datagram too large for buffer: %d > %d", len(data), len(b))
	}
	return copy(b, data), nil
}

func (c *PacketFrameConn) Close() error                       { return c.inner.Close() }
func (c *PacketFrameConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *PacketFrameConn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *PacketFrameConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *PacketFrameConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *PacketFrameConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
