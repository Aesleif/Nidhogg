package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Command identifies the type of tunnel request.
type Command byte

const (
	CommandTCP       Command = 0x01
	CommandUDP       Command = 0x02
	CommandTelemetry Command = 0x03
)

// AddrType identifies the address encoding format.
type AddrType byte

const (
	AddrIPv4   AddrType = 0x01
	AddrDomain AddrType = 0x02
	AddrIPv6   AddrType = 0x03
)

// Destination represents a parsed tunnel destination with binary encoding.
type Destination struct {
	Command Command
	Host    string
	Port    uint16
}

// Addr returns "host:port" string representation.
func (d Destination) Addr() string {
	return net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
}

// Network returns "tcp" or "udp" based on the command.
func (d Destination) Network() string {
	if d.Command == CommandUDP {
		return "udp"
	}
	return "tcp"
}

// ParseDestination parses a string like "host:port" or "udp:host:port" into a Destination.
func ParseDestination(s string) (Destination, error) {
	cmd := CommandTCP
	if strings.HasPrefix(s, "udp:") {
		cmd = CommandUDP
		s = s[4:]
	} else if strings.HasPrefix(s, "tcp:") {
		s = s[4:]
	}

	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return Destination{}, fmt.Errorf("invalid destination %q: %w", s, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return Destination{}, fmt.Errorf("invalid port %q", portStr)
	}

	return Destination{
		Command: cmd,
		Host:    host,
		Port:    uint16(port),
	}, nil
}

// WriteDest encodes a Destination in binary format and writes it to w.
//
// Wire format:
//
//	[command:1B] [addr_type:1B] [address:variable] [port:2B BE]
//
// For CommandTelemetry, only the command byte is written (no address/port).
func WriteDest(w io.Writer, d Destination) error {
	if _, err := w.Write([]byte{byte(d.Command)}); err != nil {
		return err
	}
	if d.Command == CommandTelemetry {
		return nil
	}

	ip := net.ParseIP(d.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		if _, err := w.Write([]byte{byte(AddrIPv4)}); err != nil {
			return err
		}
		if _, err := w.Write(ip.To4()); err != nil {
			return err
		}
	case ip != nil:
		if _, err := w.Write([]byte{byte(AddrIPv6)}); err != nil {
			return err
		}
		if _, err := w.Write(ip.To16()); err != nil {
			return err
		}
	default:
		if len(d.Host) > 255 {
			return fmt.Errorf("domain too long: %d bytes", len(d.Host))
		}
		if _, err := w.Write([]byte{byte(AddrDomain), byte(len(d.Host))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(d.Host)); err != nil {
			return err
		}
	}

	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], d.Port)
	_, err := w.Write(portBuf[:])
	return err
}

// ReadDest reads a binary-encoded Destination from r.
func ReadDest(r io.Reader) (Destination, error) {
	var cmdBuf [1]byte
	if _, err := io.ReadFull(r, cmdBuf[:]); err != nil {
		return Destination{}, fmt.Errorf("read command: %w", err)
	}
	cmd := Command(cmdBuf[0])

	if cmd == CommandTelemetry {
		return Destination{Command: CommandTelemetry}, nil
	}

	if cmd != CommandTCP && cmd != CommandUDP {
		return Destination{}, fmt.Errorf("unknown command: 0x%02x", cmd)
	}

	var typeBuf [1]byte
	if _, err := io.ReadFull(r, typeBuf[:]); err != nil {
		return Destination{}, fmt.Errorf("read addr type: %w", err)
	}

	var host string
	switch AddrType(typeBuf[0]) {
	case AddrIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return Destination{}, fmt.Errorf("read ipv4: %w", err)
		}
		host = net.IP(addr[:]).String()
	case AddrIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return Destination{}, fmt.Errorf("read ipv6: %w", err)
		}
		host = net.IP(addr[:]).String()
	case AddrDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return Destination{}, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			return Destination{}, fmt.Errorf("zero-length domain")
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(r, domain); err != nil {
			return Destination{}, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	default:
		return Destination{}, fmt.Errorf("unknown addr type: 0x%02x", typeBuf[0])
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return Destination{}, fmt.Errorf("read port: %w", err)
	}

	return Destination{
		Command: cmd,
		Host:    host,
		Port:    binary.BigEndian.Uint16(portBuf[:]),
	}, nil
}
