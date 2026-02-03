# Repository Guidelines

## Project Structure & Module Organization
- Root package files (`*.go`) implement GMTLS primitives, handshakes, and crypto helpers (`cipher.go`, `handshake.go`, `sm2.go`, `sm3.go`, `sm4.go`, `tls13*.go`).
- `cmd/` contains runnable examples and tools:
  - `cmd/cnnic_epp` CNNIC EPP client.
- `cnnic/` holds configuration and example GM certificates/keys (`cnnic/config.yml`, `cnnic/gm/*`).
- `internal/legacy` keeps legacy implementations for reference only (excluded from builds via tags).

## Build, Test, and Development Commands
- `go run ./cmd/cnnic_epp -config cnnic/config.yml -action hello` runs the EPP client against the sample config.
- `go test ./...` is the standard Go test command (no tests currently live in this repo).

## Coding Style & Naming Conventions
- Use standard Go formatting: run `gofmt` on all modified `.go` files.
- Naming follows Go conventions: `CamelCase` for exported identifiers, `mixedCase` for unexported.
- Keep crypto-related constants descriptive (e.g., `HANDSHAKE_SM2_ID`) and colocate with relevant logic.
- The project uses `github.com/emmansun/gmsm` for SM2/SM3/SM4 internals while keeping public `gmtls` types stable.

## Testing Guidelines
- No test suite is present yet. If adding tests, use Go’s built-in `testing` package.
- Place tests alongside sources using `*_test.go` naming (e.g., `handshake_test.go`).

## Commit & Pull Request Guidelines
- Git history shows minimal commit messages (`init`). There is no enforced convention yet.
- Suggested convention: short, imperative summaries (e.g., “Add TLS 1.3 ticket parsing”).
- PRs should include: summary of changes, how to run relevant commands, and any protocol-impact notes.

## Security & Configuration Tips
- Treat `cnnic/gm/*.key` as sensitive; avoid committing real private keys.
- Keep `cnnic/config.yml` aligned with the server environment (host, cert paths, EPP action).
- When changing TLS defaults or cipher choices, document compatibility impacts in `README.md`.
