# Issue: Upgrade tower-http to 0.7

## Metadata

- ID: 20261123-2153
- Created: 2026-11-23-21-53
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261123-2151` Periodic Dependency Updates and Security Audit

## Problem

`tower-http` is still at 0.6 (`Cargo.toml`: `version = "0.6"`,
features `cors`, `fs`). 0.7.1 is available.

The upgrade was left out of PR #356 because it is a breaking change for
users of the `cors` feature of `oauth2-passkey-axum`:

- `oauth2_passkey_axum/src/cors.rs` exposes
  `pub fn cors_layer() -> Option<CorsLayer>`, re-exported from
  `lib.rs`. `CorsLayer` from 0.7 is a different type from 0.6, so
  applications that combine it with their own tower-http 0.6 layers
  would break.
- 0.7.0 also changes CORS behavior: "`cors`: relax the `Vary` header
  defaults".

Other notes from the 0.7.0 / 0.7.1 changelog:

- Most breaking changes are in `compression`, `follow-redirect`, `fs`,
  `trace` and `classify`. This crate uses only `cors` in library code.
- MSRV of tower-http 0.7 is 1.65 (ours is 1.94).
- `reqwest` 0.13.5 still depends on tower-http 0.6, so both versions
  would be in the build until reqwest updates.

## Timeline

## Latest Plan

Do it in a release that allows breaking changes (0.7.0).

### Files

- `Cargo.toml`
- `oauth2_passkey_axum/src/cors.rs`
- `CHANGELOG.md` (note the public type change)

### Implementation Tasks

- [ ] Bump `tower-http` to 0.7 and fix compile errors, if any
- [ ] Check the `Vary` header change against the CORS tests
- [ ] Note the `cors_layer()` type change in the CHANGELOG

### Verification

- `cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features`
- `demo-cross-origin` works with the new layer.

## Resolution
