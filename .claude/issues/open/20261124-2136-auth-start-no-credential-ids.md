# Issue: Stop Returning Credential IDs from Unauthenticated auth/start; Require Discoverable Credentials

## Metadata

- ID: 20261124-2136
- Created: 2026-11-24-21-36
- Closed:
- Status: open
- Priority: high
- Difficulty: medium
- Related Issues:
  - `20261116-0111` Re-authentication (Step-up) Design Policy (related)
  - `20261124-2138` Passkey Registration Could Overwrite Another User's Credential (completed)

## Problem

`POST /passkey/auth/start` accepts an optional `username` in the body.
When present, `start_authentication` looks up that user's credentials
(`name2cid_str_vec`) and returns their credential IDs in
`allowCredentials`. The endpoint is unauthenticated, so anyone can
obtain a user's credential IDs and learn whether a username exists.

WebAuthn L3 references: §14.6.2 (username enumeration), §14.6.3
(privacy leak via credential IDs; suggests performing another
authentication step first, using discoverable credentials, or
returning imaginary credential IDs).

Based on examination of the code on 2026-11-16:

- The bundled JS never sends `username`: `passkey.js` sends `{}`,
  `conditional_ui.js` sends `null`.
- `PASSKEY_RESIDENT_KEY` defaults to `required`; non-discoverable
  credentials are possible only when it is configured otherwise.
- Credential ID disclosure was one of the steps in the registration
  vulnerability fixed in 0.6.2 (GHSA-f7r7-vc8j-f293).

## Timeline

### 2026-11-16 — Decision

Options considered: (A) always return empty `allowCredentials` for
unauthenticated requests; (B) config flag for the username lookup;
(D) return the session user's IDs for re-auth; (E) imaginary IDs.

Chosen: A, together with requiring discoverable credentials. B and E
not chosen. D is deferred to the re-authentication work
(`20261116-0111`) as a separate authenticated endpoint.

Target: 0.7.0 (behavior change).

## Latest Plan

1. Remove the username -> credential ID lookup:
   `name2cid_str_vec`, the username branch in `start_authentication`,
   and `username` in the body of `handle_start_authentication_core`.
2. Abolish `PASSKEY_RESIDENT_KEY` and `PASSKEY_REQUIRE_RESIDENT_KEY`;
   fix them to `required` / `true`. If set, log a warning and ignore
   (no startup error).
3. Update docs and CHANGELOG (existing non-discoverable credentials
   can no longer be used to log in).

### Files

- `oauth2_passkey/src/passkey/main/auth.rs`
- `oauth2_passkey/src/coordination/passkey.rs`
- `oauth2_passkey/src/passkey/config.rs`
- `docs/src/.../configuration.md`, `passkey.md`, `dot.env.example`,
  `demo-live/README.md`

### Implementation Tasks

- [ ] Remove username lookup from auth/start
- [ ] Rewrite tests that use `username`: `passkey_flows.rs` (lines 166,
      491, 823), `secure_auth.rs` (line 138),
      `coordination/passkey/tests.rs` (around lines 764, 814)
- [ ] Fix resident key settings to required, warn when set
- [ ] Docs and CHANGELOG

### Verification

- auth/start with any body returns empty `allowCredentials`.
- Discoverable-credential login (passkey.js, conditional UI) works.
- Full test suite, clippy, fmt.

## Resolution
