package shaper

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/aesleif/nidhogg/internal/profile"
)

// ShapingMode controls how aggressively traffic is shaped.
type ShapingMode int

const (
	// Disabled means no shaping is applied.
	Disabled ShapingMode = -1
	// Stream pads packet sizes only, no timing delays. Best for video/downloads.
	Stream ShapingMode = iota
	// Balanced pads sizes and groups writes into bursts. Default mode.
	Balanced
	// Stealth pads sizes, applies timing delays, and groups into bursts.
	Stealth
)

// ParseMode maps a config string to a ShapingMode.
// Empty string returns Disabled.
func ParseMode(name string) (ShapingMode, error) {
	switch name {
	case "":
		return Disabled, nil
	case "stream":
		return Stream, nil
	case "balanced":
		return Balanced, nil
	case "stealth":
		return Stealth, nil
	default:
		return Disabled, fmt.Errorf("unknown shaping mode: %q", name)
	}
}

// Frame format:
//   [frame_size: 2 bytes big-endian] [payload_length: 2 bytes big-endian] [payload: N bytes] [padding: M bytes]
//
// frame_size = 2 + N + M  (everything after frame_size field)
// Total wire bytes = 2 + frame_size = 4 + N + M
//
// The target wire size for each frame is drawn from profile.SampleSize().

const (
	frameSizeLen   = 2 // frame_size header
	payloadLenSize = 2 // payload_length header
	frameOverhead  = frameSizeLen + payloadLenSize
	minFrameSize   = frameOverhead + 1 // at least 1 byte of payload
	maxPayload     = 65535 - payloadLenSize
)

// ShapedConn wraps a net.Conn with traffic shaping based on a Profile.
type ShapedConn struct {
	net.Conn
	prof *profile.Profile
	mode ShapingMode

	writeMu    sync.Mutex
	burstCount int // frames sent in current burst (Balanced/Stealth)

	readMu  sync.Mutex
	readBuf []byte // leftover payload from partial reads
}

// NewShapedConn wraps conn with traffic shaping.
func NewShapedConn(conn net.Conn, prof *profile.Profile, mode ShapingMode) *ShapedConn {
	return &ShapedConn{
		Conn: conn,
		prof: prof,
		mode: mode,
	}
}

// Write encodes b into one or more shaped frames and writes them to the connection.
func (c *ShapedConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalWritten := 0
	remaining := b

	for len(remaining) > 0 {
		if err := c.applyTiming(); err != nil {
			return totalWritten, err
		}

		targetSize := c.prof.SampleSize()
		if targetSize < minFrameSize {
			targetSize = minFrameSize
		}

		// Max payload that fits in this frame
		maxChunk := targetSize - frameOverhead
		if maxChunk > maxPayload {
			maxChunk = maxPayload
		}

		chunk := remaining
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}

		if err := c.writeFrame(chunk, targetSize); err != nil {
			return totalWritten, err
		}
		totalWritten += len(chunk)
		remaining = remaining[len(chunk):]
	}

	return totalWritten, nil
}

// Read decodes one frame from the connection and returns the payload.
func (c *ShapedConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Return buffered data first
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	payload, err := c.readFrame()
	if err != nil {
		return 0, err
	}

	// Skip padding-only frames (payload_length == 0)
	for len(payload) == 0 {
		payload, err = c.readFrame()
		if err != nil {
			return 0, err
		}
	}

	n := copy(b, payload)
	if n < len(payload) {
		c.readBuf = payload[n:]
	}
	return n, nil
}

// writeFrame writes a single frame with the given payload, padded to targetSize total wire bytes.
func (c *ShapedConn) writeFrame(payload []byte, targetSize int) error {
	wireSize := frameOverhead + len(payload)
	paddingLen := 0
	if targetSize > wireSize {
		paddingLen = targetSize - wireSize
	}

	frameContentSize := payloadLenSize + len(payload) + paddingLen // frame_size value

	frame := make([]byte, frameSizeLen+frameContentSize)
	binary.BigEndian.PutUint16(frame[0:2], uint16(frameContentSize))
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	// padding bytes are already zero

	_, err := c.Conn.Write(frame)
	return err
}

// readFrame reads a single frame and returns the payload (without padding).
func (c *ShapedConn) readFrame() ([]byte, error) {
	// Read frame_size (2 bytes)
	var header [frameSizeLen]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return nil, fmt.Errorf("read frame size: %w", err)
	}
	frameContentSize := int(binary.BigEndian.Uint16(header[:]))

	if frameContentSize < payloadLenSize {
		return nil, fmt.Errorf("frame content size too small: %d", frameContentSize)
	}

	// Read entire frame content
	content := make([]byte, frameContentSize)
	if _, err := io.ReadFull(c.Conn, content); err != nil {
		return nil, fmt.Errorf("read frame content: %w", err)
	}

	payloadLen := int(binary.BigEndian.Uint16(content[0:2]))
	if payloadLen > frameContentSize-payloadLenSize {
		return nil, fmt.Errorf("payload length %d exceeds frame content %d", payloadLen, frameContentSize)
	}

	payload := make([]byte, payloadLen)
	copy(payload, content[payloadLenSize:payloadLenSize+payloadLen])
	// Rest is padding — discard

	return payload, nil
}

// applyTiming adds delays based on the shaping mode.
func (c *ShapedConn) applyTiming() error {
	switch c.mode {
	case Stealth:
		time.Sleep(c.prof.SampleTiming())
	case Balanced:
		c.burstCount++
		if c.burstCount >= c.prof.AvgBurstLen {
			c.burstCount = 0
			pause := c.prof.BurstPause
			if pause.Max > 0 {
				d := pause.Min + time.Duration(rand.Int64N(int64(pause.Max-pause.Min+1)))
				time.Sleep(d)
			}
		}
	}
	return nil
}
