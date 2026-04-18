# Contributing to Nidhogg

## Getting started

```bash
git clone https://github.com/aesleif/nidhogg.git
cd nidhogg
go build ./...
go test ./...
```

## Development setup

- **Go 1.22+** required
- No CGo dependencies
- All code must pass `go vet ./...` and `gofmt`

## Code style

- Format with `gofmt` (no exceptions)
- Use `log/slog` for all logging (structured, leveled)
- Keep packages in `internal/` &mdash; no exported API guarantees
- Prefer short, focused functions over large ones
- No comments explaining *what* the code does &mdash; only *why* when non-obvious

## Pull requests

1. One PR = one logical change (feature, bugfix, or refactor)
2. Include tests for new functionality
3. Write a clear description: what changed and why
4. Ensure `go build ./...` and `go test ./...` pass
5. Keep commits atomic and well-described

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
