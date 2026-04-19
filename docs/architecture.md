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
  Body: [handshake:57B] [destination] [client_profile_version:4B] [shaping_mode:1B] [payload...]

  Handshake     = [version:1B = 0x01] [timestamp:8B BE millis] [nonce:16B] [hmac-sha256:32B]
  HMAC covers   : version + timestamp + nonce, key = PSK
  destination   : binary TLV — see "Destination encoding" below
  shaping_mode  : 0=disabled, 1=stream, 2=balanced, 3=stealth
```

Non-matching requests are forwarded to the reverse proxy target (cover traffic).

`shaping_mode` lets the server know whether the client will frame its traffic
via `ShapedConn`. The server only frames the relay (in both directions) when
`shaping_mode != 0` AND it has an active profile — otherwise it relays raw
bytes. Mismatched framing would corrupt the entire stream.

### Destination encoding

```
[command:1B] [addr_type:1B] [address:variable] [port:2B BE]

  command    : 0x01=TCP, 0x02=UDP, 0x03=Telemetry
  addr_type  : 0x01=IPv4 (4B), 0x02=Domain (1B length + bytes), 0x03=IPv6 (16B)
```

For `command = 0x03 (Telemetry)` only the command byte is written; no
address or port follows.

### Profile delivery

After the server accepts a tunnel, it responds with the current traffic
profile inline. The 4-byte version header lets the client skip re-parsing
when it already cached the profile:

```
Server -> Client:
  200 OK
  X-Nidhogg-Tunnel: 1
  Body: [profile_version:4B BE CRC32] [profile_size:4B BE] [profile_json?] [relay data...]
```

- `profile_version == 0` AND `profile_size == 0`: server has no active profile.
- `profile_version != 0` AND `profile_size == 0`: client already has this version (matched `client_profile_version`).
- `profile_version != 0` AND `profile_size > 0`: full JSON payload follows.

### Telemetry

Telemetry uses the same endpoint with `command = 0x03`:

```
Client -> Server:
  POST / HTTP/2
  Body: [handshake:57B] [0x03] [client_profile_version:4B] [0x00] [report_json]

Server -> Client:
  200 OK
  X-Nidhogg-Tunnel: 1
  Body: [profile_version:4B] [profile_size:4B] [profile_json?]
```

The `shaping_mode` byte is always `0x00` for telemetry — there is no
relay to shape.

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
