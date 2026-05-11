# Issue: Use constant-time comparison in verify_page_session_token

## Metadata

- ID: 20260512-0350
- Created: 2026-05-12-03-50
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2018` Simplify OAuth2 Account Linking API (parent — surfaced as a side finding in its Timeline entry on 2026-05-12T02:46)

## Problem

`verify_page_session_token` at
`oauth2_passkey/src/session/main/page_session_token.rs:107` compares
the candidate token to the expected HMAC using plain `!=`:

```rust
if context.as_str() != generate_page_session_token(&stored_session.csrf_token) {
    return Err(SessionError::PageSessionToken(...));
}
```

`docs/src/security/csrf.md:132-146` mandates constant-time
comparison (`subtle::ConstantTimeEq`) for CSRF-class tokens, with
an explicit "❌ Bad - vulnerable to timing attacks" warning against
plain `!=`. The `page_session_token` check is inconsistent with the
project's own stated security policy.

Practical risk is low — Rust string `==` typically delegates to a
memcmp implementation that is empirically near-constant-time for
equal-length inputs, and HMAC outputs are 32 bytes so direct
byte-by-byte search is not meaningful — but the inconsistency
should be eliminated to bring the codebase in line with its
documented policy.

## Timeline

### 2026-05-12T03:50 — Issue created from parent's side findings

Surfaced during the analysis recorded in `20260226-2018` Timeline
entry 2026-05-12T02:46.

## Latest Plan

Replace the non-constant-time comparison with `subtle::ConstantTimeEq`,
matching the pattern documented in `docs/src/security/csrf.md` and
applied for form-CSRF verification in `demo-both/src/protected.rs`.

Implementation sketch:

```rust
use subtle::ConstantTimeEq;

let expected = generate_page_session_token(&stored_session.csrf_token);
let context_bytes = context.as_bytes();
let expected_bytes = expected.as_bytes();

// HMAC outputs are always the same length, but compare defensively.
if context_bytes.len() != expected_bytes.len()
    || !bool::from(context_bytes.ct_eq(expected_bytes))
{
    return Err(SessionError::PageSessionToken(
        "Page session token does not match session user".to_string(),
    ));
}
```

`subtle` is already a transitive dependency in this workspace.

### Files

- `oauth2_passkey/src/session/main/page_session_token.rs` — the fix
- `oauth2_passkey/src/session/main/page_session_token/tests.rs` — verify existing tests still pass

### Implementation Tasks

- [ ] Replace `!=` with `subtle::ConstantTimeEq` per implementation sketch
- [ ] Verify existing `page_session_token` unit tests pass
- [ ] Run `cargo fmt --all` and `cargo clippy --all-targets --all-features`
- [ ] Run full workspace test suite

### Verification

- `cargo test` passes
- `cargo clippy --all-targets --all-features` clean
- Existing tests `test_verify_page_session_token_success`, `_invalid_token`, `_missing_token`, `_missing_session` continue to pass

## Resolution
