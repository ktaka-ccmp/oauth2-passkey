# Issue: Passkey Login While Logged In Silently Switches Account

## Metadata

- ID: 20261116-0112
- Created: 2026-11-16-01-12
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261116-0111` Re-authentication (Step-up) Design Policy (related)

## Problem

When a user already has a valid session and performs a passkey login,
the library does not consider the existing session. If the asserted
passkey belongs to a different account, the user is silently logged in
as that other account.

Mechanism (based on examination of the code on 2026-11-16):

- `handle_start_authentication` (`oauth2_passkey_axum/src/passkey.rs`)
  takes only the JSON body; no session is extracted.
- `handle_finish_authentication_core`
  (`oauth2_passkey/src/coordination/passkey.rs`) verifies the
  assertion and calls `new_session_header()` for the credential owner,
  returning a new session cookie. There is no comparison with the
  existing session's user.

Result: user A logged in -> passkey login with B's passkey -> no error,
the session cookie is replaced and the user is now B. This is
acceptable for a plain login, but it is surprising UX when it happens
unintentionally (e.g. shared device with several accounts' passkeys).

Whether the OAuth2 login path behaves the same way was not examined.

## Timeline

### 2026-11-16T01:12 — UX options

Candidate behaviors:

1. If already logged in, do not show the login page; redirect to the
   account page.
2. Allow switching only through an explicit "switch account" action.

Either way, account switching should be an intentional action rather
than a side effect of a passkey assertion.

## Latest Plan

Not scheduled. Decide between the options above, then implement.

### Files

- `oauth2_passkey_axum/src/passkey.rs`
- `oauth2_passkey/src/coordination/passkey.rs`
- `oauth2_passkey_axum/templates/login.j2`

### Implementation Tasks

- [ ] Check whether the OAuth2 login path has the same behavior
- [ ] Decide the intended UX (redirect vs. explicit switch)
- [ ] Implement and add tests

### Verification

- Logged-in user cannot unintentionally switch accounts via passkey login.

## Resolution
