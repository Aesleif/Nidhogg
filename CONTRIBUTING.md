# Contributing to Nidhogg

## Getting started

```bash
git clone https://github.com/aesleif/nidhogg.git
cd nidhogg
go build ./...
go test ./...
```

## Development setup

- **Go 1.26+** required
- No CGo dependencies
- All code must pass `go vet ./...` and `gofmt`

## Code style

- Format with `gofmt` (no exceptions)
- Use `log/slog` for all logging (structured, leveled)
- Keep internal packages in `internal/`. Public API is in `pkg/nidhogg/` &mdash; maintain backward compatibility there
- Prefer short, focused functions over large ones
- No comments explaining *what* the code does &mdash; only *why* when non-obvious

## Pull requests

1. One PR = one logical change (feature, bugfix, or refactor)
2. Include tests for new functionality
3. Write a clear description: what changed and why
4. Ensure `go build ./...` and `go test ./...` pass
5. Keep commits atomic and well-described

## Testing patterns

- **HTTP/2 in unit tests** &mdash; use `golang.org/x/net/http2/h2c` to spin up
  cleartext h2 servers via `httptest`. See `internal/client/pool_test.go`
  and `internal/server/tunnel_test.go` for the pattern.
- **Regression tests for known bugs** &mdash; name them after the failure
  scenario and include a comment explaining what broke before the fix.
  Examples: `TestTunnelEchoServerProfileClientNoShape`,
  `TestTunnelEchoUDPWithShaping`, `TestRecordingConnCapsSamples`.
- **Running a subset** &mdash; `go test ./internal/client/... -run TestPool -v`
- **Race detector** &mdash; for any change touching `internal/client/pool.go`,
  `internal/transport/handshake.go`, or shaper buffers, run with `-race`.

## Issues

### Bug reports

Include:
- Go version and OS
- Config (redact PSK)
- Full error log with `log_level: "debug"`
- Steps to reproduce

### Feature requests

Describe the use case, not just the solution. Context helps us evaluate trade-offs.

## Architecture

See [docs/architecture.md](docs/architecture.md) for package structure, protocol details, and design decisions.
