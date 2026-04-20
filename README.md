# Nidhogg

Adaptive anti-censorship protocol with traffic shaping over HTTP/2.

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

## What is Nidhogg?

Nidhogg tunnels network traffic through an HTTPS reverse proxy using HTTP/2 POST streams. It captures real HTTPS traffic profiles and applies adaptive packet shaping to make tunneled connections indistinguishable from legitimate web browsing. When a traffic profile degrades, the system automatically switches to an alternative profile without dropping active connections.

**Key features:**

- HTTP/2 POST streaming tunnel over TLS with multi-connection client pool and periodic connection recycling
- Adaptive traffic shaping from real HTTPS profiles (CDF-based packet sizing and timing)
- uTLS fingerprint randomization (Chrome, Firefox, Safari, or random)
- PSK-authenticated handshake (HMAC-SHA256 with replay-protected nonce)
- Automatic profile rotation on connection degradation
- UDP over TCP (UoT) -- tunnel UDP datagrams (QUIC, DNS) through the TCP tunnel
- Per-connection health monitoring with server telemetry feedback
- Idle-timeout on tunnels and bounded internal state -- designed for long uptimes
- Built-in pprof endpoint (loopback) for heap / goroutine / CPU diagnostics
- Public Go API (`pkg/nidhogg`) for embedding in proxy frameworks (Xray-core, sing-box)
- Server appears as a normal HTTPS reverse proxy to external observers

## How it works

```mermaid
sequenceDiagram
    participant App
    participant Client as nidhogg-client<br/>(SOCKS5)
    participant Server as nidhogg-server<br/>(HTTPS reverse proxy)
    participant Target as Destination

    App->>Client: SOCKS5 CONNECT / UDP ASSOCIATE host:port
    Client->>Server: HTTP/2 POST [handshake + dest + version + shaping_mode]
    Server-->>Client: 200 OK + [version + size + profile JSON]

    loop Shaped relay
        App->>Client: plaintext data
        Client->>Server: shaped frames [size|payload|padding]
        Server->>Target: raw TCP
        Target-->>Server: response
        Server-->>Client: shaped frames
        Client-->>App: plaintext data
    end

    Note over Client: Health monitor detects degradation
    Client->>Server: telemetry report (_telemetry)
    Server-->>Client: updated profile
    Note over Client: Switcher rotates profile
```

## Quick start

### Prerequisites

- Go 1.26+
- A server with a public IP and domain (for production)

### Build

```bash
go build -o nidhogg-server ./cmd/nidhogg-server
go build -o nidhogg-client ./cmd/nidhogg-client
```

### Server setup

Create `config.json`:

```json
{
  "listen": ":443",
  "domain": "your-domain.com",
  "psk": "your-secret-key",
  "cover_upstream": "www.microsoft.com:443",
  "profile_targets": ["google.com"],
  "log_level": "info"
}
```

```bash
./nidhogg-server -config config.json
```

The server obtains a TLS certificate via Let's Encrypt automatically. For manual certificates, set `cert_file` and `key_file`.

The `cover_upstream` setting is dual-purpose: connections whose TLS SNI
doesn't match `domain` are raw-TCP-forwarded to the cover site (probers
see that site's real cert and TLS handshake byte-for-byte), and HTTP
requests on the matching domain that fail PSK validation are reverse-
proxied to the same site. Pick a stable, unrelated HTTPS site
(`www.microsoft.com:443`, `cdn.cloudflare.com:443`, etc.).

### Client setup

Create `client.json`:

```json
{
  "server": "your-domain.com:443",
  "psk": "your-secret-key",
  "listen": "127.0.0.1:1080",
  "shaping_mode": "balanced",
  "log_level": "info"
}
```

```bash
./nidhogg-client -config client.json
```

Configure your browser or application to use `127.0.0.1:1080` as a SOCKS5 proxy.

## Configuration

### Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | `":443"` | Listen address |
| `domain` | string | required* | Domain for Let's Encrypt |
| `psk` | string | required | Pre-shared key for tunnel authentication |
| `cover_upstream` | string | required | Real HTTPS site as `host:port`. Used as raw-TCP forward target for non-matching SNIs (defeats IP-range scanners) and as HTTP fallback target when PSK validation fails |
| `tunnel_path` | string | `"/"` | HTTP path for tunnel endpoint |
| `cert_file` | string | | TLS certificate file (alternative to Let's Encrypt) |
| `key_file` | string | | TLS private key file |
| `profile_targets` | []string | `["google.com"]` | Target sites for traffic profile generation |
| `profile_interval` | string | `"6h"` | Profile regeneration interval |
| `profile_min_snapshots` | int | `20` | Minimum traffic snapshots before regeneration |
| `telemetry_critical_threshold` | int | `3` | Critical reports before triggering profile regeneration |
| `log_level` | string | `"info"` | Log level: debug, info, warn, error |

*Required when `cert_file` is not set.

### Client

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server` | string | required | Server address (host:port) |
| `psk` | string | required | Pre-shared key (must match server) |
| `listen` | string | `"127.0.0.1:1080"` | SOCKS5 proxy listen address |
| `tunnel_path` | string | `"/"` | Tunnel endpoint path (must match server) |
| `insecure` | bool | `false` | Skip TLS certificate verification |
| `fingerprint` | string | `"randomized"` | TLS fingerprint: randomized, chrome, firefox, safari |
| `shaping_mode` | string | `""` | Traffic shaping mode (see below) |
| `log_level` | string | `"info"` | Log level: debug, info, warn, error |
| `max_rtt_ms` | int | `2000` | Maximum handshake RTT before critical (ms) |
| `consecutive_failures` | int | `3` | Write errors before marking connection critical |
| `telemetry_interval` | string | `"30s"` | Health telemetry reporting interval |
| `connection_pool_size` | int | `4` | Parallel TCP+TLS connections (1 = single conn) |
| `idle_timeout` | string | `"5m"` | Close a tunnel after no Read/Write activity for this duration |
| `connection_max_age` | string | `"1h"` | Recycle pooled HTTP/2 connections older than this (graceful shutdown + redial) |

### Shaping modes

| Mode | Description |
|------|-------------|
| *(empty)* | No shaping, raw relay |
| `stream` | Padding only &mdash; fixed frame sizes, no timing changes |
| `balanced` | Padding + burst pattern emulation |
| `stealth` | Padding + bursts + inter-packet timing delays from profile CDF |

## Architecture

Nidhogg is organized into focused internal packages:

| Package | Purpose |
|---------|---------|
| `transport` | TLS dialing with uTLS, PSK handshake generation/validation |
| `client` | Dialer with HTTP/2 connection pool, profile cache |
| `server` | Tunnel handler, reverse proxy fallback, profile manager |
| `shaper` | Traffic shaping: frame encoding, CDF sampling, burst emulation |
| `profile` | Profile definition, generation from traffic snapshots, LRU cache |
| `pcap` | Bounded traffic recording from real HTTPS connections |
| `health` | Per-connection monitoring, degradation detection, aggregate tracking |
| `telemetry` | Client-to-server health reporting, server-side aggregation |
| `switcher` | Profile cache with atomic switching and callbacks |
| `udprelay` | UDP datagram framing for UoT |
| `logging` | Structured logging setup (`log/slog`) |

See [docs/architecture.md](docs/architecture.md) for protocol details and design decisions.

## Integration

Nidhogg is integrated as a full protocol (`"protocol": "nidhogg"`) in a
[forked Xray-core](https://github.com/aesleif/Xray-core), supporting both
inbound (server) and outbound (client) handlers including UDP dispatch.
A typical gateway deployment puts Xray on a tproxy box with the nidhogg
outbound, multiplexing all client TCP/UDP through the HTTP/2 tunnel.

The public Go API in `pkg/nidhogg/` provides `Client` and `Server` types for
embedding into other proxy frameworks. Server-side integrators implement the
relay loop themselves and call `Server.ShapeRelay(...)` to wrap traffic in
shaping when the active profile and the client's `shaping_mode` agree.

## Roadmap

See [docs/roadmap.md](docs/roadmap.md) for what's done, what's coming next (active probing hardening, multi-PSK auth, sing-box integration, release engineering), and longer-term ideas.

## Security

See [SECURITY.md](SECURITY.md) for the security model, known limitations, and how to report vulnerabilities.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## License

Nidhogg is licensed under the [GNU General Public License v3.0](LICENSE).
