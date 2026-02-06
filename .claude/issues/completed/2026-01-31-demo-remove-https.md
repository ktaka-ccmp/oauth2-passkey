# Issue: Remove Unnecessary HTTPS Support from Demo Applications

## ID: 2026-01-31-02

## Status: completed

## Priority: low

## Description

Remove built-in HTTPS support from demo applications. Since `localhost` is a secure context (WebAuthn works over HTTP), and production deployments should use HTTPS proxies (nginx/Caddy), the built-in TLS code adds unnecessary complexity.

## Background

This follows the simplification done for `demo-cross-origin` (commit ce6c895), where Direct HTTPS support was removed in favor of:

1. **localhost** - Development (HTTP, no setup required)
2. **HTTPS Proxy** - Production (nginx/Caddy terminates TLS)

The same reasoning applies to other demo applications.

## Affected Demos

All 6 demos with HTTPS support were updated:

- demo-both
- demo-oauth2
- demo-passkey
- demo-custom-login
- demo-todo
- demo-profile

## Rationale

1. **localhost is secure context**: WebAuthn works over HTTP on localhost
2. **HTTPS Proxy is production standard**: nginx/Caddy handle TLS better
3. **Simpler code**: Less dependencies, easier to maintain
4. **Consistent approach**: All demos follow same pattern

## Acceptance Criteria

- [x] demo-both: Remove HTTPS support, HTTP-only
- [x] demo-both: Remove `self_signed_certs/` directory
- [x] demo-both: Update README with HTTPS Proxy instructions
- [x] demo-oauth2: Check and remove HTTPS if present
- [x] demo-passkey: Check and remove HTTPS if present
- [x] demo-custom-login: Check and remove HTTPS if present
- [x] demo-todo: Check and remove HTTPS if present
- [x] demo-profile: Check and remove HTTPS if present
- [x] All demos pass `cargo fmt`, `cargo clippy`, `cargo test`
- [x] Update READMEs referencing demo HTTPS ports

## Related

- Commit ce6c895: `refactor(demo-cross-origin): remove Direct HTTPS support, simplify to HTTP-only`
- Issue 2026-01-30-09: Cross-Origin Same-Site Demo (completed with simplification notes)

## Resolution

Completed in commit 7947252 on branch `dev-2026-01-31-02`.

Changes per demo:
- `server.rs`: Removed `spawn_https_server()`, simplified to HTTP-only using `tokio::net::TcpListener`
- `main.rs`: Removed rustls initialization, removed `spawn_https_server()` call
- `Cargo.toml`: Removed `axum-server` and `rustls` dependencies
- `README.md`: Updated URLs from `https://localhost:3443` to `http://localhost:3001`
- `self_signed_certs/`: Deleted

**Stats**: 43 files changed, 115 insertions(+), 868 deletions(-)