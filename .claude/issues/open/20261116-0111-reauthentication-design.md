# Issue: Re-authentication (Step-up) Design Policy

## Metadata

- ID: 20261116-0111
- Created: 2026-11-16-01-11
- Closed:
- Status: open
- Priority: low
- Difficulty: large
- Related Issues:
  - `20261116-0112` Passkey login while logged in silently switches account (related: login endpoints must not be reused for re-auth)

## Problem

The library has no re-authentication (step-up / "sudo mode") feature.
Sensitive operations (account deletion, passkey deletion, OAuth2
unlink, admin operations) run on the strength of an existing session
alone. The only trace of the idea is a note in
`docs/src/archived/ToDo.md:61` ("On-demand re-authentication when API
access needed").

The existing passkey login endpoints (`/passkey/auth/start`,
`/passkey/auth/finish`) cannot be reused for re-authentication as-is:
they do not look at the current session at all, and `finish` always
issues a new session for whichever user owns the asserted credential
(`handle_finish_authentication_core` -> `new_session_header`). Using
them for re-auth would let a different account's passkey "pass"
re-auth and silently switch the session.

This issue records the intended design so that a future implementation
follows it.

## Timeline

### 2026-11-16T01:11 — Design discussion summary

Points agreed during discussion:

- **Separate endpoints (or an explicit mode)** for re-auth. Login and
  re-auth differ in `finish` semantics (new session vs. identity
  confirmation only), so they should not share an entry point.
- **`allowCredentials` from the session user only.** For re-auth the
  server already knows the user, so returning that user's own
  credential IDs is safe (WebAuthn L3 §14.6.3 lists "perform a separate
  authentication step ... before exposing the user's credential IDs" as
  a preventive measure). Credential IDs must never be derived from a
  client-supplied identity such as a username. Benefit is UX: only the
  user's own passkeys are offered, avoiding the multi-account picker.
- **Server-side ownership check is mandatory.** `allowCredentials` is a
  client hint and cannot be trusted. `finish` must verify that the
  asserted credential's `user_id` equals the session user, and fail
  otherwise. On mismatch, show a clear message ("this passkey belongs
  to a different account") and never switch the session.
- **Offer the methods the user actually has.** OAuth2-only users must
  be able to re-authenticate via OAuth2 (`prompt=login` or `max_age`,
  then check `auth_time` in the ID token). Passkey-only re-auth would
  lock OAuth2-only users out of sensitive operations.
- **Freshness window.** Record the last authentication time in the
  session and skip re-auth within N minutes (e.g. 5) to avoid repeated
  prompts during consecutive operations.
- **User verification required** for re-auth (UV flag must be set),
  independent of the login-time `PASSKEY_USER_VERIFICATION` setting.
- **Cancel** simply aborts the pending operation and returns to the
  previous screen; the session is untouched.

## Latest Plan

Not scheduled. When implemented:

### Files

- `oauth2_passkey/src/coordination/passkey.rs` (new re-auth start/finish core functions)
- `oauth2_passkey/src/coordination/oauth2.rs` (OAuth2 re-auth path)
- `oauth2_passkey/src/session/` (last-authenticated timestamp)
- `oauth2_passkey_axum/src/passkey.rs`, `oauth2_passkey_axum/src/oauth2.rs` (routes)
- `oauth2_passkey_axum/static/` (re-auth dialog)

### Implementation Tasks

- [ ] Define which operations require re-auth and the freshness window
- [ ] Passkey re-auth start: `allowCredentials` from session user's credentials
- [ ] Passkey re-auth finish: ownership check, UV required, no new session, record re-auth time
- [ ] OAuth2 re-auth path with `auth_time` verification
- [ ] Frontend dialog offering the user's available methods
- [ ] Unit, integration, and E2E tests (including wrong-account passkey rejection)

### Verification

- Re-auth with own passkey succeeds and the operation proceeds.
- Re-auth with another account's passkey fails with a clear message and the session is unchanged.
- OAuth2-only user can complete re-auth.
- Within the freshness window, no prompt is shown.

## Resolution
