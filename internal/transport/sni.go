package transport

import (
	"encoding/binary"
	"errors"
)

// ErrShortBuffer means the caller hasn't read enough TLS bytes yet —
// re-read more data and call PeekSNI again.
var ErrShortBuffer = errors.New("transport: short buffer for ClientHello")

// ErrNotClientHello means the buffer doesn't look like a TLS handshake
// ClientHello at all (wrong record type, version, or message type).
var ErrNotClientHello = errors.New("transport: not a TLS ClientHello")

// PeekSNI parses a TLS ClientHello from buf and returns the SNI hostname
// and ALPN protocol list, if present. It does NOT validate the rest of
// the handshake — it just skips fields to reach the extensions block.
//
// Returns ErrShortBuffer if buf is truncated mid-field; the caller should
// read more bytes and try again. Returns ErrNotClientHello if the bytes
// clearly aren't a TLS handshake.
//
// Reference: RFC 5246 §7.4.1.2 (ClientHello), RFC 6066 §3 (server_name),
// RFC 7301 (ALPN).
func PeekSNI(buf []byte) (sni string, alpn []string, err error) {
	r := newReader(buf)

	// TLS record header: type(1) + version(2) + length(2)
	recType, err := r.byte()
	if err != nil {
		return "", nil, err
	}
	if recType != 22 { // handshake
		return "", nil, ErrNotClientHello
	}
	if _, err := r.bytes(2); err != nil { // version
		return "", nil, err
	}
	if _, err := r.bytes(2); err != nil { // record length
		return "", nil, err
	}

	// Handshake header: type(1) + length(3)
	hsType, err := r.byte()
	if err != nil {
		return "", nil, err
	}
	if hsType != 1 { // ClientHello
		return "", nil, ErrNotClientHello
	}
	if _, err := r.bytes(3); err != nil { // length
		return "", nil, err
	}

	// ClientHello body: client_version(2) + random(32) + session_id_len(1) + ...
	if _, err := r.bytes(2); err != nil {
		return "", nil, err
	}
	if _, err := r.bytes(32); err != nil {
		return "", nil, err
	}
	sidLen, err := r.byte()
	if err != nil {
		return "", nil, err
	}
	if _, err := r.bytes(int(sidLen)); err != nil {
		return "", nil, err
	}

	// cipher_suites
	csLenBytes, err := r.bytes(2)
	if err != nil {
		return "", nil, err
	}
	csLen := int(binary.BigEndian.Uint16(csLenBytes))
	if _, err := r.bytes(csLen); err != nil {
		return "", nil, err
	}

	// compression_methods
	cmLen, err := r.byte()
	if err != nil {
		return "", nil, err
	}
	if _, err := r.bytes(int(cmLen)); err != nil {
		return "", nil, err
	}

	// extensions
	extLenBytes, err := r.bytes(2)
	if err != nil {
		// No extensions block — return what we have (no SNI/ALPN).
		return "", nil, nil
	}
	extLen := int(binary.BigEndian.Uint16(extLenBytes))
	extBuf, err := r.bytes(extLen)
	if err != nil {
		return "", nil, err
	}

	er := newReader(extBuf)
	for er.remaining() > 0 {
		extTypeBytes, err := er.bytes(2)
		if err != nil {
			return sni, alpn, nil
		}
		extType := binary.BigEndian.Uint16(extTypeBytes)

		extDataLenBytes, err := er.bytes(2)
		if err != nil {
			return sni, alpn, nil
		}
		extDataLen := int(binary.BigEndian.Uint16(extDataLenBytes))
		extData, err := er.bytes(extDataLen)
		if err != nil {
			return sni, alpn, nil
		}

		switch extType {
		case 0x0000: // server_name
			sni, _ = parseSNIExtension(extData)
		case 0x0010: // ALPN
			alpn, _ = parseALPNExtension(extData)
		}
	}

	return sni, alpn, nil
}

// parseSNIExtension extracts the first host_name from a server_name
// extension value.
//
// Format: server_name_list_length(2) + entries
// Entry: name_type(1) + name_length(2) + name(var). Only name_type=0
// (host_name) is defined.
func parseSNIExtension(data []byte) (string, error) {
	r := newReader(data)
	listLenBytes, err := r.bytes(2)
	if err != nil {
		return "", err
	}
	listLen := int(binary.BigEndian.Uint16(listLenBytes))
	listData, err := r.bytes(listLen)
	if err != nil {
		return "", err
	}
	lr := newReader(listData)
	for lr.remaining() > 0 {
		nameType, err := lr.byte()
		if err != nil {
			return "", err
		}
		nameLenBytes, err := lr.bytes(2)
		if err != nil {
			return "", err
		}
		nameLen := int(binary.BigEndian.Uint16(nameLenBytes))
		name, err := lr.bytes(nameLen)
		if err != nil {
			return "", err
		}
		if nameType == 0 {
			return string(name), nil
		}
	}
	return "", nil
}

// parseALPNExtension returns the protocol list.
// Format: protocol_name_list_length(2) + entries.
// Entry: name_length(1) + name(var).
func parseALPNExtension(data []byte) ([]string, error) {
	r := newReader(data)
	listLenBytes, err := r.bytes(2)
	if err != nil {
		return nil, err
	}
	listLen := int(binary.BigEndian.Uint16(listLenBytes))
	listData, err := r.bytes(listLen)
	if err != nil {
		return nil, err
	}
	var out []string
	lr := newReader(listData)
	for lr.remaining() > 0 {
		nameLen, err := lr.byte()
		if err != nil {
			return out, err
		}
		name, err := lr.bytes(int(nameLen))
		if err != nil {
			return out, err
		}
		out = append(out, string(name))
	}
	return out, nil
}

// reader is a tiny cursor for byte-by-byte parsing with bounds checks.
type reader struct {
	buf []byte
	off int
}

func newReader(b []byte) *reader { return &reader{buf: b} }

func (r *reader) byte() (byte, error) {
	if r.off >= len(r.buf) {
		return 0, ErrShortBuffer
	}
	b := r.buf[r.off]
	r.off++
	return b, nil
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrShortBuffer
	}
	if r.off+n > len(r.buf) {
		return nil, ErrShortBuffer
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *reader) remaining() int { return len(r.buf) - r.off }
