package server

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestCheckIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr string // substring; empty means no error expected
	}{
		{"public v4", "8.8.8.8", ""},
		{"public v6", "2001:4860:4860::8888", ""},

		{"loopback v4", "127.0.0.1", "loopback"},
		{"loopback v4 range", "127.5.6.7", "loopback"},
		{"loopback v6", "::1", "loopback"},

		{"rfc1918 10/8", "10.0.0.1", "private"},
		{"rfc1918 172.16/12", "172.16.5.5", "private"},
		{"rfc1918 192.168/16", "192.168.1.1", "private"},
		{"rfc6598 cgnat", "100.64.0.1", "private"},
		{"rfc4193 ula", "fd00::1", "private"},

		{"link-local v4", "169.254.1.1", "link-local"},
		{"link-local v6", "fe80::1", "link-local"},

		{"multicast v4", "224.0.0.1", "multicast"},
		{"multicast v6", "ff02::1", "multicast"},

		{"unspecified v4", "0.0.0.0", "unspecified"},
		{"unspecified v6", "::", "unspecified"},

		{"ipv4-mapped private", "::ffff:10.0.0.1", "private"},
		{"ipv4-mapped loopback", "::ffff:127.0.0.1", "loopback"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) = nil", tc.ip)
			}
			err := checkIP(ip)
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("checkIP(%s) = %v, want nil", tc.ip, err)
				}
				return
			}
			if err == nil {
				t.Errorf("checkIP(%s) = nil, want error containing %q", tc.ip, tc.wantErr)
				return
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("checkIP(%s) = %v, want substring %q", tc.ip, err, tc.wantErr)
			}
		})
	}
}

func TestResolveAndCheck_IPLiteral(t *testing.T) {
	acl := DefaultDestACL{}
	ctx := context.Background()

	// Allowed: public IP passes.
	if ip, err := acl.ResolveAndCheck(ctx, "8.8.8.8"); err != nil || !ip.Equal(net.ParseIP("8.8.8.8")) {
		t.Errorf("public IP: ip=%v err=%v", ip, err)
	}

	// Denied: private IP.
	if _, err := acl.ResolveAndCheck(ctx, "10.0.0.1"); err == nil {
		t.Error("expected error for private IP literal")
	}

	// Denied: loopback.
	if _, err := acl.ResolveAndCheck(ctx, "127.0.0.1"); err == nil {
		t.Error("expected error for loopback literal")
	}
	if _, err := acl.ResolveAndCheck(ctx, "::1"); err == nil {
		t.Error("expected error for ipv6 loopback literal")
	}
}
