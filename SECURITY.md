# Security Policy

## Supported versions

Nidhogg is currently in active development and has not reached a stable release. Security fixes are applied to the `master` branch.

| Version | Supported |
|---------|-----------|
| master (dev) | Yes |

## Reporting a vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email: **contact@aesleif.com**
3. Include: description, reproduction steps, potential impact
4. Expected response time: **72 hours**

## Security model

### What Nidhogg protects against

- **Passive DPI:** Traffic shaping makes tunneled connections statistically similar to real HTTPS browsing (CDF-based packet sizing, optional burst pattern emulation, optional inter-packet timing delays)
- **TLS client fingerprinting:** uTLS randomizes ClientHello to match real browsers (Chrome, Firefox, Safari)
- **Unauthorized tunnel access:** PSK authentication via HMAC-SHA256 (57-byte handshake marker including version, timestamp, random nonce, MAC)
- **Replay attacks (within bounds):** Nonce ring with timestamp window (±60s clock skew). Hard-capped at 10K entries to prevent unbounded memory; see weaknesses below for the trade-off.

### What Nidhogg does NOT protect against

- **Active probing fingerprint:** The TLS handshake is performed by Go's `crypto/tls`, whose cipher and extension order differs from nginx, Cloudflare, or popular CDNs. A determined active prober (e.g. ZGrab2 + JA3S classifier) can distinguish "this is a Go HTTP server pretending to be a website" from a genuine origin. VLESS-Reality avoids this by SNI-multiplexing the TLS handshake to a real upstream site; Nidhogg currently does not.
- **Long-lived HTTP/2 connection pattern:** A handful of long-lived TCP connections each carrying thousands of multiplexed streams is atypical browser behavior. Stateful DPI may flag this as anomalous.
- **Replay window after hard-cap eviction:** When the nonce map exceeds 10K entries under sustained load, arbitrary fresh entries are dropped to keep memory bounded. This opens a ~60-second window where evicted-but-still-fresh nonces could be replayed. Acceptable trade-off vs unbounded growth, but weaker than a pure LRU.
- **Endpoint compromise:** If the server or client machine is compromised, all traffic is exposed.
- **Traffic correlation:** An adversary observing both ends of the tunnel can correlate connections by volume and timing despite shaping.
- **Multi-user key isolation:** All clients share a single PSK; compromising one client exposes the key for all. No per-user authentication exists yet.
- **Auth-layer forward secrecy:** PSK + HMAC has no forward secrecy. If the PSK leaks, all future handshakes from any client can be forged. (TLS gives FS on the data channel via ECDHE, but that protects the bytes, not the auth.)
- **No third-party crypto / security audit:** Single-author project, no external review. Absence of known issues is not evidence of safety.
- **Server bandwidth amplification via reverse proxy fallback:** A bogus handshake forwards the request to the configured reverse-proxy upstream. Picking a heavy upstream means an attacker can use Nidhogg as a free request relay — pick a static cover site.

### Known limitations

- **Not a VPN** &mdash; Standalone Nidhogg is a SOCKS5 proxy. When integrated with Xray-core, it can work as a system-wide transparent proxy (tproxy), but this depends on the framework configuration.
- **Single PSK** &mdash; All clients authenticate with the same key. There is no per-user authentication or access control. Multi-PSK / per-user UUID auth is on the [roadmap](docs/roadmap.md).
- **Profile quality** &mdash; Traffic shaping effectiveness depends on how closely the profile targets match real browsing patterns. Poor target selection reduces evasion quality.

## Threat model

Nidhogg is designed to evade **automated** censorship systems (DPI) that
classify and block traffic based on statistical fingerprints. It targets
adversaries at the level of the Russian TSPU or similar nation-scale
filters operating on aggregated flow data and basic active probing.

It is **not** designed to withstand:

- A well-resourced adversary capable of TLS server-side fingerprint
  classification at scale (where VLESS-Reality is currently stronger)
- Targeted investigation with access to both endpoints
- Adversaries running heuristics specifically tuned for Nidhogg's HTTP/2
  multiplexing pattern

For high-stakes use cases (journalists in authoritarian regimes, activists
under targeted surveillance), a more mature protocol with peer-reviewed
crypto and active probing resistance is recommended.
