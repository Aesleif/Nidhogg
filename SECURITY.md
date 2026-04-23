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
- **Unauthorized tunnel access:** Ed25519 challenge-response authentication. The client sends `[version:1][pubkey:32]`; the server returns a fresh 32-byte `crypto/rand` nonce; the client signs `"nidhogg-auth-v2\x00" || nonce` with its private key; the server verifies against the public key looked up in `authorized_keys`. Replay is impossible because the nonce is unique per connection.
- **Client revocation:** each client has its own Ed25519 keypair. Removing the corresponding line from `authorized_keys` and restarting the server blocks that client immediately without affecting the others.
- **Server-compromise damage scope:** an attacker who gains root on the server reads the `authorized_keys` list. These are public keys by design — they cannot be used to impersonate any client because the matching private keys never leave the client machines. No shared secret exists that, if leaked, would unlock every client.
- **IP-range scanners with arbitrary SNIs (partial):** The standalone server peeks every TLS ClientHello and raw-TCP-forwards connections whose SNI doesn't match `cover_upstream`'s configured domain to a real HTTPS site. Probes targeting `google.com`, `cloudflare.com`, etc. on our IP get that site's actual certificate and TLS handshake. Targeted probes that use our specific domain bypass this — they still hit the regular nidhogg path (see weaknesses below).
- **Destination abuse from authenticated clients:** the server's ACL rejects tunnel destinations that resolve to loopback, RFC 1918, CGNAT, link-local, or multicast addresses before `net.Dial`, and dials by the resolved IP literal to prevent DNS-rebinding between check and dial.

### What Nidhogg does NOT protect against

- **Active probing fingerprint:** The TLS handshake is performed by Go's `crypto/tls`, whose cipher and extension order differs from nginx, Cloudflare, or popular CDNs. A determined active prober (e.g. ZGrab2 + JA3S classifier) can distinguish "this is a Go HTTP server pretending to be a website" from a genuine origin. VLESS-Reality avoids this by SNI-multiplexing the TLS handshake to a real upstream site; Nidhogg currently does not.
- **Long-lived HTTP/2 connection pattern:** A handful of long-lived TCP connections each carrying thousands of multiplexed streams is atypical browser behavior. Stateful DPI may flag this as anomalous.
- **Endpoint compromise:** If the server or client machine is compromised, all traffic is exposed.
- **Client private-key theft:** if an attacker steals a client's `private_key`, they can impersonate that specific client until the pubkey is removed from `authorized_keys`. Only one client is affected; there is no shared secret that cascades to others.
- **Auth-layer forward secrecy:** Ed25519 signatures are not forward-secret in the sense that a stolen private key lets the attacker authenticate from any point forward. Rotate via `nidhogg-keygen` + `authorized_keys` edit. TLS ECDHE still provides forward secrecy on the data channel.
- **Traffic correlation:** An adversary observing both ends of the tunnel can correlate connections by volume and timing despite shaping.
- **No third-party crypto / security audit:** Single-author project, no external review. Absence of known issues is not evidence of safety.
- **Server bandwidth amplification via reverse proxy fallback:** A handshake that fails authentication forwards the request to the configured reverse-proxy upstream. Picking a heavy upstream means an attacker can use Nidhogg as a free request relay — pick a static cover site.
- **No server-side rate limiting on the tunnel path:** a remote peer that already has a valid client private key (or a valid authorized pubkey that can reach the challenge phase) is not throttled. A stolen key used to pound the server is mitigated only by removing the pubkey.
- **Local pprof endpoint exposure:** The standalone server and client bind `net/http/pprof` to `127.0.0.1:6060` / `:6061` for diagnostics. The loopback bind is the security boundary — there is no auth. On a multi-tenant box, any other local user or process able to connect to `127.0.0.1` can pull heap dumps, which contain whatever was in process memory at the time (client: its Ed25519 private key; server: the `authorized_keys` list, which is public by design but still identifies your users). Mitigation: deploy on single-tenant boxes only, gate the port with a host firewall, or build with the pprof block removed for production binaries.

### Known limitations

- **Not a VPN** &mdash; Standalone Nidhogg is a SOCKS5 proxy. When integrated with Xray-core, it can work as a system-wide transparent proxy (tproxy), but this depends on the framework configuration.
- **No hot-reload of `authorized_keys`** &mdash; adding or revoking a client requires a server restart. Hot-reload via SIGHUP is on the [roadmap](docs/roadmap.md).
- **No per-client rate-limiting** &mdash; the server treats all authenticated clients equally. Planned.
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
