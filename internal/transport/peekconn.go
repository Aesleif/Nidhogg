package transport

import (
	"io"
	"net"
)

// PeekConn wraps a net.Conn so the caller can read the first N bytes
// without consuming them: subsequent Reads return those bytes again,
// then continue with normal stream reads.
//
// Used by the SNI router to inspect a TLS ClientHello before deciding
// whether to terminate TLS locally or forward the raw TCP elsewhere.
type PeekConn struct {
	net.Conn
	peeked []byte
	pos    int
}

// NewPeekConn wraps c. Caller may call Peek any time before the first
// Read; mixing them is safe as long as Peek is not called after Read
// has already consumed past the peek buffer.
func NewPeekConn(c net.Conn) *PeekConn {
	return &PeekConn{Conn: c}
}

// Peek returns up to n bytes from the start of the stream without
// consuming them. May return fewer bytes than requested if EOF is
// reached, paired with io.EOF / io.ErrUnexpectedEOF. Subsequent Peek
// calls return the same data (possibly extended).
func (p *PeekConn) Peek(n int) ([]byte, error) {
	if n <= len(p.peeked) {
		return p.peeked[:n], nil
	}
	need := n - len(p.peeked)
	buf := make([]byte, need)
	got, err := io.ReadFull(p.Conn, buf)
	p.peeked = append(p.peeked, buf[:got]...)
	if err != nil {
		return p.peeked, err
	}
	return p.peeked[:n], nil
}

// Read returns peeked bytes first, then continues with the underlying
// conn.
func (p *PeekConn) Read(b []byte) (int, error) {
	if p.pos < len(p.peeked) {
		n := copy(b, p.peeked[p.pos:])
		p.pos += n
		if p.pos == len(p.peeked) {
			// Drop the buffer reference to free memory.
			p.peeked = nil
		}
		return n, nil
	}
	return p.Conn.Read(b)
}
