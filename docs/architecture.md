# Architecture

## Package structure

```
cmd/
  nidhogg-client/     SOCKS5 proxy client
  nidhogg-server/     HTTPS reverse proxy + tunnel server

internal/
  transport/          TLS dialing (uTLS), PSK handshake
  shaper/             Traffic shaping (framing, CDF sampling)
  profile/            Profile struct, generation, LRU cache
  pcap/               Traffic recording from real connections
  health/             Connection monitoring, degradation detection
  telemetry/          Client-server health reporting
  switcher/           Profile cache with atomic switching
  logging/            Structured logging (slog)
  udprelay/           UDP datagram framing for UoT
  client/             Dialer, client config
  server/             Tunnel handler, reverse proxy, profile manager, server config

pkg/
  nidhogg/            Public API for external consumers (Xray-core, sing-box)
```

## Package dependencies

```
cmd/nidhogg-client
  -> client -> transport, profile, shaper
  -> health
  -> switcher -> profile
  -> telemetry -> health, profile, transport
  -> udprelay

cmd/nidhogg-server
  -> server -> transport, profile, shaper, pcap, telemetry, udprelay
  -> telemetry

pkg/nidhogg (public API)
  -> client, server, transport, profile, shaper
```

## Protocol

### Tunnel handshake

All tunnel and telemetry traffic flows through the same HTTP endpoint (default `/`).

```
Client -> Server:
  POST / HTTP/2
  Content-Type: application/octet-stream
  Body: [handshake:57B] [destination\n] [payload...]

  Handshake = [timestamp:8B] [random:17B] [hmac-sha256:32B]
  HMAC covers: timestamp + random, key = PSK
```

Non-matching requests are forwarded to the reverse proxy target (cover traffic).

### Profile delivery

After the server accepts a tunnel, it responds with the active traffic profile inline:

```
Server -> Client:
  200 OK
  X-Nidhogg-Tunnel: 1
  Body: [profile_size:4B BE] [profile_json] [relay data...]
```

If `profile_size == 0`, no profile is available and shaping is skipped.

### Telemetry

Telemetry uses the same endpoint with a special destination marker:

```
Client -> Server:
  POST / HTTP/2
  Body: [handshake:57B] [_telemetry\n] [report_json]

Server -> Client:
  200 OK
  Body: [profile_size:4B] [profile_json or empty]
```

Report format:
```json
{
  "profile": "google.com",
  "status": "healthy|degraded|critical",
  "avg_rtt_ms": 145,
  "error_count": 0
}
```

The server responds with the current active profile, allowing clients to receive updated profiles through telemetry without opening a new tunnel.

### UDP over TCP (UoT)

UDP datagrams are tunneled through the same TCP stream with length-prefix framing.

Destination format supports a network prefix:
- `host:port\n` -- TCP (default, backward compatible)
- `tcp:host:port\n` -- TCP (explicit)
- `udp:host:port\n` -- UDP

UDP datagram framing inside the tunnel stream:

```
[2B big-endian length][datagram payload]
[2B big-endian length][datagram payload]
...
```

UDP traffic is not shaped -- datagrams are framed directly. Maximum datagram size: 65535 bytes.

## Traffic shaping

### Frame format

ShapedConn wraps each payload in a fixed-size frame:

```
[frame_size:2B BE] [payload_length:2B BE] [payload] [padding]
```

- `frame_size`: total frame size (sampled from profile CDF)
- `payload_length`: actual data bytes in this frame
- `padding`: random bytes to fill the frame

### Shaping modes

| Mode | Padding | Burst emulation | Timing delays |
|------|---------|-----------------|---------------|
| Stream | Yes | No | No |
| Balanced | Yes | Yes | No |
| Stealth | Yes | Yes | Yes (from profile CDF) |

### Profile generation

Profiles are generated from real HTTPS traffic:

1. `pcap.Collect()` connects to target sites and records packet metadata
2. `profile.Generate()` builds CDF distributions for send/receive sizes and inter-packet timing
3. `shaper.NewShapedConn()` samples from these CDFs to determine frame sizes

## Health monitoring

### Per-connection monitoring

`MonitoredConn` wraps `net.Conn` and tracks:
- Handshake RTT (measured during `DialTunnel`)
- Write errors (consecutive count, reset on success)
- Read timeouts (only `net.Error` with `Timeout() == true`)
- Write latency (ring buffer of 10 samples)

### Degradation levels

| Level | Condition |
|-------|-----------|
| Healthy | No issues detected |
| Degraded | 2+ read timeouts, 1+ write errors, or latency > 50% threshold |
| Critical | Thresholds breached: RTT > max, errors >= limit, timeouts >= limit, or latency > max |

### Auto-adaptation chain

```
MonitoredConn.checkLevel()       detects level change
  -> OnDegradation callback      fires in client main
    -> Tracker.AggregateLevel()  checks worst across all connections
      -> Switcher.Switch()       rotates to next cached profile
        -> OnSwitch callback     updates Dialer.ProfileOverride
          -> next DialTunnel     uses new profile for ShapedConn
```

Existing connections continue with their original profile (graceful drain).
