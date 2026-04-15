package transport

import (
	"context"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// FingerprintID maps a fingerprint name to a utls ClientHelloID.
// Supported values: "" or "randomized", "chrome", "firefox", "safari".
// StandardTLS is a zero-value ClientHelloID that signals the dialer
// to use standard crypto/tls instead of uTLS. Used for testing.
var StandardTLS = utls.ClientHelloID{}

func FingerprintID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "", "randomized":
		return utls.HelloRandomized, nil
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "standard":
		return StandardTLS, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unknown fingerprint: %q", name)
	}
}

// DialTLS establishes a TLS connection using uTLS with the specified
// fingerprint. The connection negotiates HTTP/2 via ALPN.
func DialTLS(ctx context.Context, network, addr string, insecure bool, helloID utls.ClientHelloID) (net.Conn, error) {
	dialer := net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("split host port: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
	}

	uConn := utls.UClient(tcpConn, tlsConfig, helloID)
	if err := uConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	if proto := uConn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("expected ALPN h2, got %q", proto)
	}

	return uConn, nil
}
