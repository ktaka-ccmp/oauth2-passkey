# Issue: AuthUser CSRF Check Compares Content-Type Case-Sensitively

## Metadata

- ID: 20261125-1004
- Created: 2026-11-25-10-04
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

When a state-changing request has no `X-CSRF-Token` header, the
`AuthUser` extractor lets it through only if the Content-Type is a form
type (the handler is then expected to check a form token). The extractor
compares the Content-Type case-sensitively, while the core function used
by the middleware lowercases it first. Media types are case-insensitive
(RFC 9110 §8.3.1), so the two paths disagree for a value such as
`Application/x-www-form-urlencoded`.

Raised by an external review (Gemini via `agy`, 2026-11-25); checked
against origin/dev 13fde6c:

- `oauth2_passkey_axum/src/session.rs:217-243` (`AuthUser`
  extractor): `ct.starts_with("application/x-www-form-urlencoded") ||
  ct.starts_with("multipart/form-data")` without lowercasing; a
  non-form Content-Type without the header is rejected.
- `oauth2_passkey/src/session/main/session.rs:398-425` (used by the
  `is_authenticated_*` middleware via `oauth2_passkey_axum/src/middleware.rs`):
  the same check on `ct.to_lowercase()` (since `9b284a0`, 2025-05-28).

Impact: fail-closed. A form POST with a non-lowercase Content-Type and
no `X-CSRF-Token` header is rejected by the extractor but accepted by
the middleware path. Browsers send lowercase values for HTML forms, so
this affects mainly non-browser clients. No security weakening.

## Timeline

## Latest Plan

Compare case-insensitively in the extractor (lowercase, or
`eq_ignore_ascii_case` on the prefix), preferably by sharing one helper
with the core check so the two cannot drift again.

### Files

- `oauth2_passkey_axum/src/session.rs`
- `oauth2_passkey/src/session/main/session.rs` (if a shared helper is
  added)

### Implementation Tasks

- [ ] Case-insensitive Content-Type check in the extractor
- [ ] Test: mixed-case form Content-Type without the header is accepted
      by both paths; non-form is rejected by both

### Verification

- `cargo test` for both crates, clippy, fmt.

## Resolution
