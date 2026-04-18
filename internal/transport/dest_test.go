package transport

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoundtripDomain(t *testing.T) {
	d := Destination{Command: CommandTCP, Host: "google.com", Port: 443}
	var buf bytes.Buffer
	if err := WriteDest(&buf, d); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Fatalf("got %+v, want %+v", got, d)
	}
}

func TestRoundtripIPv4(t *testing.T) {
	d := Destination{Command: CommandUDP, Host: "8.8.8.8", Port: 53}
	var buf bytes.Buffer
	if err := WriteDest(&buf, d); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Fatalf("got %+v, want %+v", got, d)
	}
}

func TestRoundtripIPv6(t *testing.T) {
	d := Destination{Command: CommandTCP, Host: "2001:db8::1", Port: 8080}
	var buf bytes.Buffer
	if err := WriteDest(&buf, d); err != nil {
		t.Fatal(err)
	}
	got, err := ReadDest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != d {
		t.Fatalf("got %+v, want %+v", got, d)
	}
}

func TestRoundtripTelemetry(t *testing.T) {
	d := Destination{Command: CommandTelemetry}
	var buf bytes.Buffer
	if err := WriteDest(&buf, d); err != nil {
		t.Fatal(err)
	}
	// Telemetry should be just 1 byte
	if buf.Len() != 1 {
		t.Fatalf("telemetry should be 1 byte, got %d", buf.Len())
	}
	got, err := ReadDest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CommandTelemetry {
		t.Fatalf("got command %d, want %d", got.Command, CommandTelemetry)
	}
}

func TestParseDestination(t *testing.T) {
	tests := []struct {
		input   string
		command Command
		host    string
		port    uint16
	}{
		{"google.com:443", CommandTCP, "google.com", 443},
		{"tcp:google.com:443", CommandTCP, "google.com", 443},
		{"udp:8.8.8.8:53", CommandUDP, "8.8.8.8", 53},
		{"udp:[::1]:53", CommandUDP, "::1", 53},
		{"[2001:db8::1]:8080", CommandTCP, "2001:db8::1", 8080},
		{"127.0.0.1:0", CommandTCP, "127.0.0.1", 0},
		{"example.com:65535", CommandTCP, "example.com", 65535},
	}

	for _, tt := range tests {
		d, err := ParseDestination(tt.input)
		if err != nil {
			t.Errorf("ParseDestination(%q): %v", tt.input, err)
			continue
		}
		if d.Command != tt.command || d.Host != tt.host || d.Port != tt.port {
			t.Errorf("ParseDestination(%q) = %+v, want cmd=%d host=%s port=%d",
				tt.input, d, tt.command, tt.host, tt.port)
		}
	}
}

func TestParseDestinationErrors(t *testing.T) {
	bad := []string{
		"",
		"no-port",
		"host:notanumber",
		"host:99999",
	}
	for _, s := range bad {
		_, err := ParseDestination(s)
		if err == nil {
			t.Errorf("ParseDestination(%q) should fail", s)
		}
	}
}

func TestParseAndRoundtrip(t *testing.T) {
	inputs := []string{
		"google.com:443",
		"udp:8.8.8.8:53",
		"192.168.1.1:80",
		"udp:[::1]:53",
	}
	for _, input := range inputs {
		d, err := ParseDestination(input)
		if err != nil {
			t.Fatalf("parse %q: %v", input, err)
		}
		var buf bytes.Buffer
		if err := WriteDest(&buf, d); err != nil {
			t.Fatalf("write %q: %v", input, err)
		}
		got, err := ReadDest(&buf)
		if err != nil {
			t.Fatalf("read %q: %v", input, err)
		}
		if got != d {
			t.Fatalf("roundtrip %q: got %+v, want %+v", input, got, d)
		}
	}
}

func TestWireFormat(t *testing.T) {
	// TCP google.com:443 → 01 02 0A "google.com" 01BB
	d := Destination{Command: CommandTCP, Host: "google.com", Port: 443}
	var buf bytes.Buffer
	WriteDest(&buf, d)
	b := buf.Bytes()

	if b[0] != 0x01 {
		t.Errorf("command: got 0x%02x, want 0x01", b[0])
	}
	if b[1] != 0x02 {
		t.Errorf("addr_type: got 0x%02x, want 0x02 (domain)", b[1])
	}
	if b[2] != 10 {
		t.Errorf("domain len: got %d, want 10", b[2])
	}
	if string(b[3:13]) != "google.com" {
		t.Errorf("domain: got %q, want %q", b[3:13], "google.com")
	}
	// port 443 = 0x01BB
	if b[13] != 0x01 || b[14] != 0xBB {
		t.Errorf("port: got 0x%02x%02x, want 0x01BB", b[13], b[14])
	}
}

func TestMaxDomainLength(t *testing.T) {
	d := Destination{Command: CommandTCP, Host: strings.Repeat("a", 255), Port: 80}
	var buf bytes.Buffer
	if err := WriteDest(&buf, d); err != nil {
		t.Fatalf("255-char domain should succeed: %v", err)
	}

	d.Host = strings.Repeat("a", 256)
	buf.Reset()
	if err := WriteDest(&buf, d); err == nil {
		t.Fatal("256-char domain should fail")
	}
}

func TestDestAddr(t *testing.T) {
	d := Destination{Command: CommandTCP, Host: "example.com", Port: 8080}
	if got := d.Addr(); got != "example.com:8080" {
		t.Fatalf("got %q, want %q", got, "example.com:8080")
	}
}

func TestDestNetwork(t *testing.T) {
	if (Destination{Command: CommandTCP}).Network() != "tcp" {
		t.Fatal("TCP should return tcp")
	}
	if (Destination{Command: CommandUDP}).Network() != "udp" {
		t.Fatal("UDP should return udp")
	}
}
