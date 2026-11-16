# Issue: Allow Overriding the Listen Port in Demo Applications

## Metadata

- ID: 20261117-0730
- Created: 2026-11-17-07-30
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

Most demo applications listen on a hardcoded port 3001, so they cannot
start when the port is in use, and two demos cannot run at the same
time.

Based on examination of the code on 2026-11-17:

- Hardcoded `spawn_http_server(3001, app)`: `demo-both`,
  `demo-passkey`, `demo-oauth2`, `demo-custom-login`, `demo-profile`,
  `demo-todo` (each `src/main.rs`).
- `demo-live` reads `PORT` (default 3001, `demo-live/src/main.rs:85`).
- `demo-cross-origin` reads `AUTH_PORT` and `API_PORT`.
- Every demo has its own near-identical `src/server.rs`; the servers
  bind `0.0.0.0`.
- No recorded reason for the hardcoded port was found. It dates back
  to `demo01` (renamed to `demo-both` in `ed5293b`); `PORT` was added
  only to `demo-live` in `1bfd461` when it was split from `demo-both`.

## Timeline

## Latest Plan

Read `PORT` (default 3001) in each demo, following `demo-live`.

The listen port and `ORIGIN` are independent: `ORIGIN` is the URL the
browser uses. Behind an HTTPS proxy they normally differ (e.g.
`ORIGIN='https://example.com'`, proxy -> `localhost:3001`). Only when
the browser accesses `http://localhost:<port>` directly must the port
in `ORIGIN` match. Document this in the READMEs; do not add a startup
check comparing them.

Sharing `server.rs` across demos is out of scope.

### Files

- `demo-{both,passkey,oauth2,custom-login,profile,todo}/src/main.rs`
- the corresponding `README.md` files

### Implementation Tasks

- [ ] Read `PORT` with default 3001 in each demo
- [ ] Document `PORT` and the localhost `ORIGIN` note in each README

### Verification

- Each demo starts on 3001 by default and on another port with
  `PORT=...`.
- `cargo clippy --all-targets --all-features`, `cargo fmt --all`.

## Resolution
