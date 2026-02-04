# Issue: Remove Unnecessary HTTPS Support from Demo Applications

## ID: 2026-01-31-02

## Status: open

## Priority: low

## Description

Remove built-in HTTPS support from demo applications. Since `localhost` is a secure context (WebAuthn works over HTTP), and production deployments should use HTTPS proxies (nginx/Caddy), the built-in TLS code adds unnecessary complexity.

## Background

This follows the simplification done for `demo-cross-origin` (commit ce6c895), where Direct HTTPS support was removed in favor of:

1. **localhost** - Development (HTTP, no setup required)
2. **HTTPS Proxy** - Production (nginx/Caddy terminates TLS)

The same reasoning applies to other demo applications.

## Affected Demos

### demo-both

Current behavior:

- Runs HTTP (3001) and HTTPS (3443) simultaneously
- Uses bundled self-signed certificates (`self_signed_certs/`)
- `axum-server` and `rustls` dependencies

Changes needed:

- Remove `spawn_https_server()` from `server.rs`
- Simplify `main.rs` to HTTP-only
- Remove `axum-server`, `rustls` dependencies from `Cargo.toml`
- Delete `self_signed_certs/` directory
- Update README to reflect HTTP-only + HTTPS Proxy approach
- Update default `ORIGIN` to `http://localhost:3001`

### demo-oauth2

Confirmed: Has TLS code in `server.rs`, `main.rs`, and `Cargo.toml`.
Apply same changes as demo-both.

### demo-passkey

Confirmed: Has TLS code in `server.rs`, `main.rs`, and `Cargo.toml`.
Apply same changes as demo-both.

## Rationale

1. **localhost is secure context**: WebAuthn works over HTTP on localhost
2. **HTTPS Proxy is production standard**: nginx/Caddy handle TLS better
3. **Simpler code**: Less dependencies, easier to maintain
4. **Consistent approach**: All demos follow same pattern

## Acceptance Criteria

- [ ] demo-both: Remove HTTPS support, HTTP-only
- [ ] demo-both: Remove `self_signed_certs/` directory
- [ ] demo-both: Update README with HTTPS Proxy instructions
- [ ] demo-oauth2: Check and remove HTTPS if present
- [ ] demo-passkey: Check and remove HTTPS if present
- [ ] All demos pass `cargo fmt`, `cargo clippy`, `cargo test`
- [ ] Update any documentation referencing demo HTTPS ports

## Related

- Commit ce6c895: `refactor(demo-cross-origin): remove Direct HTTPS support, simplify to HTTP-only`
- Issue 2026-01-30-09: Cross-Origin Same-Site Demo (completed with simplification notes)
