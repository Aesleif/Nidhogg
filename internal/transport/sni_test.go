package transport

import (
	"crypto/tls"
	"net"
	"slices"
	"testing"
)

// realClientHello captures a real TLS ClientHello by running tls.Client
// against a net.Pipe and snarfing what it writes.
func realClientHello(t *testing.T, serverName string, alpn []string) []byte {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()

	cfg := &tls.Config{
		ServerName:         serverName,
		NextProtos:         alpn,
		InsecureSkipVerify: true,
	}
	uc := tls.Client(client, cfg)

	// Handshake will block waiting for ServerHello — capture from server side
	// then bail out.
	captured := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		captured <- buf[:n]
		server.Close()
	}()

	go func() { _ = uc.Handshake() }()
	defer client.Close()

	return <-captured
}

func TestPeekSNI_Real(t *testing.T) {
	hello := realClientHello(t, "example.com", []string{"h2", "http/1.1"})

	sni, alpn, err := PeekSNI(hello)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "example.com" {
		t.Errorf("sni = %q, want example.com", sni)
	}
	if !slices.Contains(alpn, "h2") {
		t.Errorf("alpn = %v, want h2 present", alpn)
	}
}

func TestPeekSNI_NoSNI(t *testing.T) {
	// IP-only ClientHello has no server_name extension.
	hello := realClientHello(t, "", nil)

	sni, _, err := PeekSNI(hello)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "" {
		t.Errorf("sni = %q, want empty", sni)
	}
}

func TestPeekSNI_Truncated(t *testing.T) {
	hello := realClientHello(t, "example.com", nil)

	// Cut off mid-extensions.
	short := hello[:len(hello)/2]
	_, _, err := PeekSNI(short)
	if err == nil {
		t.Fatal("expected error on truncated buffer")
	}
}

func TestPeekSNI_NotHandshake(t *testing.T) {
	// random non-TLS bytes
	junk := []byte{0x47, 0x45, 0x54, 0x20, 0x2f} // "GET /"
	_, _, err := PeekSNI(junk)
	if err != ErrNotClientHello {
		t.Errorf("err = %v, want ErrNotClientHello", err)
	}
}

func TestPeekSNI_DifferentSNI(t *testing.T) {
	hello := realClientHello(t, "www.microsoft.com", []string{"h2"})

	sni, _, err := PeekSNI(hello)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "www.microsoft.com" {
		t.Errorf("sni = %q, want www.microsoft.com", sni)
	}
}
