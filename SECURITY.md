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

- **Deep Packet Inspection (DPI):** Traffic shaping makes tunneled connections statistically similar to real HTTPS browsing
- **TLS fingerprinting:** uTLS randomizes ClientHello to match real browsers (Chrome, Firefox, Safari)
- **Passive traffic analysis:** CDF-based packet sizing and timing patterns resist statistical classification
- **Unauthorized tunnel access:** PSK authentication via HMAC-SHA256 (57-byte handshake marker)

### What Nidhogg does NOT protect against

- **Active probing:** A determined adversary sending crafted requests to the server may distinguish it from a real web server (the reverse proxy helps, but is not foolproof)
- **Endpoint compromise:** If the server or client machine is compromised, all traffic is exposed
- **Traffic correlation:** An adversary observing both ends of the tunnel can correlate connections by volume and timing
- **Multi-user key isolation:** All clients share a single PSK; compromising one client exposes the key for all

### Known limitations

- **Not a VPN** &mdash; Standalone Nidhogg is a SOCKS5 proxy. When integrated with Xray-core, it can work as a system-wide transparent proxy (tproxy), but this depends on the framework configuration.
- **Single PSK** &mdash; All clients authenticate with the same key. There is no per-user authentication or access control.
- **Profile quality** &mdash; Traffic shaping effectiveness depends on how closely the profile targets match real browsing patterns. Poor target selection reduces evasion quality.
- **No forward secrecy beyond TLS** &mdash; The PSK is static; if compromised, past and future handshakes can be identified (though TLS provides its own forward secrecy for the data channel).

## Threat model

Nidhogg is designed to evade automated censorship systems (DPI) that classify and block traffic based on statistical fingerprints. It is **not** designed to withstand targeted investigation by a well-resourced adversary with access to both network endpoints.
