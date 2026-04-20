# Roadmap

What's done, what's next, and what might come later. Items in **Next up**
are roughly ordered by priority.

## Done

### Protocol and integrations
- Xray-core integration: full protocol (inbound + outbound), protobuf
  config, JSON config, UDP dispatch
- Public Go API in `pkg/nidhogg/` for embedding
- UDP over TCP: 2-byte length-prefix framing, SOCKS5 UDP ASSOCIATE
  support via `PacketFrameConn`
- Binary destination encoding (TLV with command/addr_type/address/port)
- Profile delivery with CRC32 versioning to skip retransmission
- Telemetry channel reusing the same endpoint with a special command byte

### Performance
- HTTP/2 server tuning: `MaxConcurrentStreams=1000`, upload buffers
  8 MiB / 64 MiB, `MaxReadFrameSize=64 KiB`
- HTTP/2 keepalive: `ReadIdleTimeout=30s` + `PingTimeout=15s` to drop
  half-dead connections
- Client connection pool: round-robin streams across N parallel TCP+TLS
  connections (default 4) to mitigate TCP head-of-line blocking
- Periodic ClientConn recycling (`connection_max_age`, default 1h) via
  graceful `Shutdown(ctx) → Close()` — prevents accumulated h2 internal
  state from degrading latency over uptime
- Client `MaxReadFrameSize=64 KiB` to amortize per-frame overhead while
  keeping per-stream scratch buffers small

### Security and reliability
- Nonce replay protection with timestamp window (±60s) and ring map
- Hard-cap on `nonces` map (prevents unbounded growth under load)
- Bounded `RecordingConn.samples` (10K cap, prevents per-connection leaks)
- Tunnel idle timeout (`transport.IdleConn`) closes Read/Write-idle
  tunnels after `idle_timeout` (default 5 min)
- Shaping mode negotiation byte (client tells server whether to frame the
  relay; mismatched framing previously corrupted every byte)
- Profile cache in client dialer (preserves shaping when server skips
  JSON via version cache)
- Reverse-proxy upstream transport with explicit `IdleConnTimeout` and
  bounded idle pool

### Active probing
- **Phase 1: SNI router** — standalone server peeks TLS ClientHello,
  raw-TCP-forwards mismatched-SNI connections to a configured
  `cover_upstream` (real HTTPS site). Probers using arbitrary SNIs
  (`google.com`, etc.) see that site's real cert and handshake
  byte-for-byte
- **`cover_upstream` doubles as HTTP-fallback target** — invalid-PSK
  requests on the matching domain are reverse-proxied to the same site,
  giving probers a probe-consistent picture across vectors

### Observability
- `net/http/pprof` endpoints on loopback (`:6060` server, `:6061` client)
- Block + mutex profiles enabled by default (full sampling rate)
- `collect-pprof.sh` fetches the full 5-profile suite (heap, goroutine,
  CPU 30s sample, block, mutex) over SSH for diff-based analysis
- ProfileManager logs p50/p95/p99 of send-size CDF on every regenerate
  for drift detection

## Next up

### Active probing hardening — Phase 2 (highest priority)

Phase 1 (SNI router with raw-TCP forward to a cover upstream) is done
and protects against IP-range scanners using arbitrary SNIs. Probes
that target our specific domain still hit the regular nidhogg path:
they see Go's `crypto/tls` ServerHello (cipher and extension order
distinguishable from nginx/cloudflare) and our Let's Encrypt cert.

- [ ] **Reality-style cert mux** — embed a PSK signature in the
  ClientHello (e.g., session ticket field) so the server can decide
  pre-handshake whether to terminate TLS locally or proxy the entire
  TLS handshake (raw bytes) to the cover upstream
- [ ] **Server-side TLS fingerprint masking** — match nginx/Cloudflare
  cipher and extension order so JA3S of our ServerHello blends in
- [ ] Document the upstream-selection trade-offs (cover site
  availability, latency, bandwidth amplification risk)

### Multi-PSK / per-user authentication

Today all clients share one PSK. Compromise of one client invalidates all.

- [ ] Server config takes a list of `{user_id, psk}` pairs (or UUID-style
  keys)
- [ ] Handshake includes a user identifier so the server validates against
  the right key
- [ ] Hot-reload: add/revoke users without restarting the server
- [ ] Per-user telemetry and rate limiting hooks

### TLS server fingerprint masking

Even with SNI mux, when nidhogg DOES terminate TLS (the tunnel handshake
itself), JA3S currently identifies it as Go.

- [ ] Configure `tls.Config` cipher suites and extension order to match a
  popular web server profile (e.g. nginx, Caddy)
- [ ] Or integrate a server-side uTLS-style library if one becomes
  available
- [ ] Validate against `ja3er.com` / similar before merging

### Server-side rate limiting

- [ ] Limit handshake attempts per source IP (e.g. 10/sec)
- [ ] Defends against active-probe spam, brute-force PSK attempts
- [ ] Should be configurable so legitimate NAT'd users aren't blocked

### Wire-protocol specification + external review

- [ ] Write `docs/spec.md` with byte-level protocol description
- [ ] Document threat model and crypto choices in detail
- [ ] Open the spec for community / paid security review
- [ ] Action item before any wider deployment recommendation

### Auto-reconnect and resilience

- [ ] Client retries with exponential backoff when server unreachable
- [ ] Fast failover between multiple configured server endpoints
- [ ] Surface server-unreachable to the user (logs, exit code)

### sing-box integration

- [ ] Fork sing-box, register `"type": "nidhogg"` outbound using
  `pkg/nidhogg`
- [ ] Implement `adapter.Outbound`: `DialContext`, `Start`, `Close`
- [ ] JSON config options matching the Xray fork
- [ ] Build tag `//go:build with_nidhogg`
- [ ] Compatibility with Hiddify, NekoBox (sing-box clients)
- [ ] Android via libbox

### Client compatibility

- [ ] v2rayN / v2rayNG / Nekoray support
- [ ] Sample configs for common client GUIs

### Local bypass (zapret-style)

- [ ] Optional `local_bypass` mode in client config
- [ ] Try direct connection with ClientHello fragmentation first
- [ ] Fall back to tunnel transparently if direct fails
- [ ] Saves server bandwidth for traffic that's already unblocked

### Release engineering

- [ ] Goreleaser multi-platform builds (`linux/{amd64,arm64}`,
  `windows/amd64`, `darwin/{amd64,arm64}`)
- [ ] Docker image for the server
- [ ] GitHub Actions CI (lint, test, build, race detector)
- [ ] First tagged release: `v0.1.0`

## Future ideas

- **PSK rotation announcement** — server pushes new PSK in profile delivery
  payload; old PSK valid for grace period
- **HTTP/3 (QUIC) transport** — would solve TCP head-of-line blocking
  cleanly, but UDP/443 is heavily blocked in Russia, so not a priority
- **Hot-reload server config** without restart (profile targets, PSK list)
- **Web UI** for server management (status, active connections, bandwidth)
- **Multi-server failover** in the client (geo-distributed gateway pool)
- **Pluggable transport** spec compliance (Tor's `pt_2.1`) — would let
  Tor Browser use Nidhogg as a bridge
- **Observability** — Prometheus metrics endpoint behind auth
- **Build tag to drop pprof** for hardened builds (heap dumps can leak
  in-memory secrets to anyone with loopback access on the host)
- **Absolute tunnel max-age** as a fallback for pseudo-active streams
  that current ClientConn recycling doesn't cover quickly enough
