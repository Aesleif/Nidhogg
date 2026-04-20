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

UDP datagrams are tunneled through the same TCP stream with length-prefix
framing. The transport command in the binary destination header
(`command = 0x02`) tells the server to dial UDP instead of TCP.

UDP datagram framing inside the tunnel stream:

```
[2B big-endian length][datagram payload]
[2B big-endian length][datagram payload]
...
```

UDP traffic is **not shaped** — the byte-stream shaper would collide with
the datagram framing layer and corrupt every packet. Both the client
dialer (`internal/client/dialer.go`) and the standalone server
(`internal/server/tunnel.go`) bypass `ShapedConn` whenever the destination
command is `CommandUDP`. Xray's inbound (`Xray-core/proxy/nidhogg/server.go`)
also skips shaping for UDP.

Maximum datagram size: 65535 bytes.

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

## Client connection pool

`internal/client/pool.go` implements `http2.ClientConnPool` to keep multiple
TCP+TLS connections to the same server and round-robin streams across them.
Default pool size is 4 (configurable via `connection_pool_size`). Pool of 1
falls back to the standard single-connection h2 transport.

Why: HTTP/2 multiplexes thousands of streams on one TCP socket, but TCP
head-of-line blocking means a single packet loss stalls every stream on
that connection. Spreading streams across N parallel sockets gives each its
own congestion window and reduces this effect — same trick browsers used to
open 6 connections per origin under HTTP/1.1.

Behavior:
- Lazy init: connections are dialed on first `GetClientConn` and as needed
  up to `size`.
- Round-robin: each call increments an `atomic.Uint64` and picks
  `conns[counter % len(alive)]`.
- Live filtering via `ClientConn.CanTakeNewRequest()` — saturated/dead
  connections are skipped.
- `MarkDead` removes a connection; the next call redials to refill.
- TLS dial reuses `transport.DialTLS` so the uTLS fingerprint is preserved
  on every pooled connection.

### Periodic recycling

Each pool slot stores a `pooledConn{cc, bornAt}`. When `GetClientConn`
sees a slot older than `maxAge` (default 1 hour, configurable via
`connection_max_age`), it asynchronously retires it:

```go
go func() {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    cc.Shutdown(ctx)  // refuses new streams, waits for in-flight to drain
    cc.Close()
}()
```

The next `GetClientConn` call dials a fresh replacement. This solves two
problems that surface only after long uptime:

1. **Stale h2 internal state** — `ClientConn.streams` is a map that
   grows monotonically as streams open and only shrinks on rehash. After
   millions of streams an aged conn carries a much larger map than its
   live stream count, slowing every operation.
2. **Stuck pseudo-active tunnels** — a tunnel that exchanges a small
   keepalive every 30s never trips the per-conn idle timer, but its
   relay goroutines are still parked on Reads that may never return
   useful data. Closing the parent ClientConn force-closes all its
   streams, freeing those goroutines and the h2 scratch buffers each
   was holding.

## Tunnel idle timeout

`internal/transport/idle.go` provides `IdleConn`, a `net.Conn` wrapper
that closes the underlying connection after a configurable period of no
Read/Write activity. It uses a single `time.AfterFunc` (no per-conn
goroutine until it fires) and `bumps` the deadline forward on every
non-zero Read or Write.

Applied on both sides:
- Client: `internal/client/dialer.go` wraps the freshly-opened
  `tunnelConn` in `IdleConn(idleTimeout)` before optional `ShapedConn`
  wrapping. Default `idleTimeout` is 5 minutes, configurable via the
  `idle_timeout` client config field.
- Server: `internal/server/tunnel.go` wraps `tcpUpstream` after `net.Dial`.
  Hardcoded 5 minutes today.

Why: `wg.Wait()` in the relay loop only returns once both directions
exit. If both Read calls block forever (silent client + silent upstream),
neither relay goroutine completes, the WaitGroup never releases, and the
handler can't run its `defer tcpUpstream.Close()`. The idle timer breaks
this stalemate by force-closing the conn, which wakes both Reads with an
error.

Limitation: a tunnel with sparse but periodic activity (websocket pings
every 30s, MTProto keepalive) keeps bumping the timer and never trips it.
That class of stuck tunnels is handled by ConnPool max-age recycling
instead — see below.

## HTTP/2 server tuning

Both standalone (`cmd/nidhogg-server/main.go` via `http2.ConfigureServer`)
and the Xray inbound (`Xray-core/proxy/nidhogg/server.go`) configure the
`http2.Server`:

| Field | Value | Why |
|-------|-------|-----|
| `MaxConcurrentStreams` | 1000 | Default 250 throttles burst tproxy load |
| `MaxUploadBufferPerStream` | 8 MiB | Default 1 MiB causes WINDOW_UPDATE round-trips on bulk uploads |
| `MaxUploadBufferPerConnection` | 64 MiB | Headroom for many parallel streams |
| `MaxReadFrameSize` | 64 KiB | Default 16 KiB is too small for bulk overhead; 1 MiB blew up per-stream scratch buffers (each h2 client stream allocates one frame-sized scratch — at 200 streams that was 200 MB). 64 KiB is the sweet spot between per-frame overhead and per-stream memory cost |
| `ReadIdleTimeout` | 30 s | Send PING after 30s of silence |
| `PingTimeout` | 15 s | Drop connection if PING is unanswered — kills hung relay goroutines on dead clients |

The client also sets `MaxReadFrameSize=64 KiB` on its `http2.Transport`.
The default client receive windows (1 GiB connection / 4 MiB per stream)
are already generous and not exposed for tuning by upstream `x/net/http2`.

## Profiling

Both the standalone server and the standalone client expose `net/http/pprof`
on a loopback-only listener (`127.0.0.1:6060` for the server,
`127.0.0.1:6061` for the client). No auth is configured — bind on loopback
is the security boundary (see [SECURITY.md](../SECURITY.md) for the
local-tenant caveat).

Both binaries also call `runtime.SetBlockProfileRate(1)` and
`runtime.SetMutexProfileFraction(1)` at startup, so `/debug/pprof/block`
and `/debug/pprof/mutex` return useful data — needed for diagnosing
latency or contention regressions that don't show up in heap.

The repo's `collect-pprof.sh` fetches all five profiles (heap, goroutine,
CPU 30s sample, block, mutex) over SSH:

```bash
ssh -L 6060:localhost:6060 server-host    # for the standalone server
ssh -L 6061:localhost:6061 client-host    # for the standalone client

./collect-pprof.sh host port login pass fresh        # right after restart
./collect-pprof.sh host port login pass degraded     # later under load
go tool pprof -top -diff_base fresh/cpu.pprof   degraded/cpu.pprof | head -20
go tool pprof -top -diff_base fresh/heap.pprof  degraded/heap.pprof | head -20
go tool pprof -top -diff_base fresh/block.pprof degraded/block.pprof | head -20
```

When nidhogg runs as an Xray outbound (`pkg/nidhogg` embedded in Xray-core),
the standalone client binary is not used. Enable pprof through Xray's own
`metrics` module instead — add to the Xray config:

```json
{
  "metrics": {
    "tag": "metrics_out",
    "listen": "127.0.0.1:6060"
  },
  "outbounds": [
    { "tag": "metrics_out", "protocol": "freedom" }
  ]
}
```

This serves `/debug/pprof/*` on `127.0.0.1:6060` inside the Xray process.
The pprof handlers are registered by `app/metrics/metrics.go` in the Xray
fork via the `_ "net/http/pprof"` import.

## Memory bounds

Several structures that previously grew without bound now have explicit
caps so the process can run for weeks under sustained load:

- **`internal/pcap/recorder.go`** — `RecordingConn.samples` is capped at
  10,000 entries (`maxSamples`). Beyond the cap, Read/Write skip the append.
  10K samples is far more than profile generation needs (CDFs are stable
  with hundreds), and the cap protects against multi-hour tunnels to
  profile-target hosts piling up `PacketSample` structs.
- **`internal/transport/handshake.go`** — `HandshakeValidator.nonces` is
  hard-capped at `nonceRingSize` (10,000). When the time-based sweep
  (`< now - 2*maxClockSkew`) cannot shrink the map (because every entry is
  fresh under sustained load), arbitrary entries are dropped down to the
  cap. Trade-off: a brief replay window for the evicted entries; see
  [SECURITY.md](../SECURITY.md) for the analysis.
- **`internal/transport/idle.go`** — `IdleConn` bounds tunnel lifetime
  by activity. Tunnels stuck on silent peers no longer leak goroutines
  and 64 KiB h2 scratch buffers indefinitely; see "Tunnel idle timeout"
  above.
- **`internal/client/pool.go`** — pooled `*http2.ClientConn` instances
  are recycled by age (default 1 hour). Per-conn h2 internal state
  (streams map, HPACK tables, frame queues) cannot accumulate beyond a
  bounded window; see "Client connection pool → Periodic recycling".

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

The dialer also keeps a `cachedProfile` (`atomic.Pointer[profile.Profile]`)
so subsequent `DialTunnel` calls can wrap streams in `ShapedConn` even when
the server skipped the JSON payload via the version-cache optimization.
Without this cache the second call would receive `prof = nil`, fall through
to a raw connection, and mismatch the still-shaping server side.
