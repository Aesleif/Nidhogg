# Roadmap

Planned features and integrations for Nidhogg. Items are roughly ordered by priority.

## Xray-core Integration

- [x] Implement Nidhogg as an Xray-core protocol (inbound + outbound)
- [x] Register protocol in Xray-core registry with protobuf config
- [x] JSON config for Xray-core protocol options (server, PSK, shaping mode)
- [x] Public Go API in `pkg/nidhogg/` for external consumers
- [ ] Compatibility with v2rayN, v2rayNG, Nekoray

## UDP over TCP (UoT)

- [x] Datagram framing with 2-byte length prefix (`internal/udprelay`)
- [x] Server-side network prefix parsing (`udp:`/`tcp:`)
- [x] SOCKS5 UDP ASSOCIATE support via `PacketFrameConn`
- [x] Xray-core UDP dispatch integration

## sing-box Integration

- [ ] Fork [sing-box](https://github.com/SagerNet/sing-box), register `"type": "nidhogg"` outbound using `pkg/nidhogg` API
- [ ] Implement `adapter.Outbound` interface: `DialContext`, `Start`, `Close`
- [ ] JSON config options: `server`, `server_port`, `psk`, `shaping_mode`
- [ ] Build tag: `//go:build with_nidhogg`
- [ ] Split tunneling: domestic traffic direct, everything else through Nidhogg
- [ ] Compatibility with Hiddify and NekoBox (sing-box core clients)
- [ ] Android support via sing-box mobile build system (libbox)

## Security Hardening

- [ ] Nonce replay protection with ring buffer (10,000 entries)
- [ ] Timestamp validation window (accept handshakes within ±60 seconds)
- [ ] PSK rotation: server announces new PSK through profile delivery
- [ ] Server-side rate limiting: max 10 new connections per second per IP

## Resilience

- [ ] Auto-reconnect with exponential backoff on connection loss
- [ ] Connection pooling: maintain 2-3 warm TLS connections for instant switchover
- [ ] Graceful degradation: log and continue when server is temporarily unreachable

## Local Bypass

Inspired by [zapret](https://github.com/bol-van/zapret):

- [ ] Optional `local_bypass` mode in client config
- [ ] Attempt direct connection with ClientHello fragmentation before tunneling
- [ ] If direct connection succeeds, use it (saves server bandwidth)
- [ ] If direct connection fails, fall back to tunnel transparently

## Release and CI

- [ ] Goreleaser config for multi-platform builds:
  - `linux/amd64`, `linux/arm64`
  - `windows/amd64`
  - `darwin/amd64`, `darwin/arm64`
- [ ] Docker image for server deployment
- [ ] GitHub Actions CI pipeline: lint, test, build
- [ ] First tagged release: `v0.1.0`
