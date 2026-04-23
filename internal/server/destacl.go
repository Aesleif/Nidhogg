package server

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// DestChecker validates and resolves tunnel destinations before dial.
// Production uses DefaultDestACL; tests pass a permissive NopDestChecker.
type DestChecker interface {
	// ResolveAndCheck returns the first allowed IP for host, or an error
	// if every resolved IP is on the deny-list. Callers should dial by
	// the returned IP literal to avoid DNS rebinding between the ACL
	// check and net.Dial's own resolution.
	ResolveAndCheck(ctx context.Context, host string) (net.IP, error)
}

// DefaultDestACL denies destinations on well-known non-routable or
// internal address ranges. It is safe-by-default with no configuration
// knob — an authenticated client must not be able to proxy into the
// server's own loopback or private network.
type DefaultDestACL struct{}

// ResolveAndCheck implements DestChecker.
func (DefaultDestACL) ResolveAndCheck(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if err := checkIP(ip); err != nil {
			return nil, err
		}
		return ip, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}

	// Deny if ANY resolved IP is blocked. Guards against split-horizon
	// DNS that returns both a public and a private answer.
	for _, ip := range ips {
		if err := checkIP(ip); err != nil {
			return nil, err
		}
	}
	return ips[0], nil
}

// NopDestChecker allows every destination. For tests only.
type NopDestChecker struct{}

// ResolveAndCheck returns the parsed IP if host is a literal, otherwise
// the first result of LookupIP — without filtering.
func (NopDestChecker) ResolveAndCheck(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no addresses")
	}
	return ips[0], nil
}

// cgnatNet is the RFC 6598 shared-address range 100.64.0.0/10 used by
// carrier-grade NAT. net.IP.IsPrivate does not cover it, but tunnelling
// into a CGNAT neighbour's session is just as undesirable as into RFC
// 1918 space, so we add an explicit check.
var cgnatNet = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// checkIP returns a non-nil error if ip falls into a denied range.
func checkIP(ip net.IP) error {
	// Canonicalize ::ffff:v4 to v4 so IPv4-mapped addresses are checked
	// against IPv4 rules (IsPrivate, IsLoopback, etc.).
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	switch {
	case ip.IsUnspecified():
		return fmt.Errorf("unspecified address: %s", ip)
	case ip.IsLoopback():
		return fmt.Errorf("loopback address: %s", ip)
	case ip.IsPrivate():
		return fmt.Errorf("private address: %s", ip)
	case cgnatNet.Contains(ip):
		return fmt.Errorf("private address (cgnat): %s", ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("link-local address: %s", ip)
	case ip.IsLinkLocalMulticast():
		return fmt.Errorf("link-local multicast: %s", ip)
	case ip.IsMulticast():
		return fmt.Errorf("multicast address: %s", ip)
	}
	return nil
}
