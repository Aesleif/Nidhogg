package server

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// NewReverseProxy returns an HTTP reverse proxy that fronts coverUpstream
// (host:port). Used as the PSK-fallback handler: requests that don't
// authenticate as nidhogg tunnels are forwarded to the cover site so the
// server looks like a regular HTTPS reverse proxy to a probing client.
func NewReverseProxy(coverUpstream string) (*httputil.ReverseProxy, error) {
	if _, _, err := net.SplitHostPort(coverUpstream); err != nil {
		return nil, fmt.Errorf("cover_upstream %q must be host:port: %w", coverUpstream, err)
	}
	target := "https://" + coverUpstream
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse cover_upstream URL %q: %w", target, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
	}

	// Own Transport with explicit timeouts and bounded idle pool.
	// Default http.DefaultTransport keeps idle conns 90s and is shared
	// process-wide; here every bogus probe / scanner request hitting the
	// PSK fallback would forward to the cover site and accumulate idle
	// conns.
	proxy.Transport = &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return proxy, nil
}
