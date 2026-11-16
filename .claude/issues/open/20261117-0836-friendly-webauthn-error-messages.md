# Issue: Show Friendly Messages for WebAuthn Browser Errors

## Metadata

- ID: 20261117-0836
- Created: 2026-11-17-08-36
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:

## Problem

When `navigator.credentials.create()` or `get()` fails, the bundled JS
shows the browser's raw message in an alert. Users cannot tell what
happened or what to do.

Example observed on 2026-11-17 when adding a passkey on an
authenticator that already holds one for the account (blocked by
`excludeCredentials`):

```
Registration failed: The user attempted to register an authenticator
that contains one of the credentials already registered with the
relying party.
```

Based on examination of the code on 2026-11-17:

- `oauth2_passkey_axum/static/passkey.js` catches all errors and calls
  `alert('Registration failed: ' + error.message)` (around line 408) or
  `alert('Authentication failed: ' + error.message)` (around line 186).
  `error.name` is not inspected.
- Server-side failures are wrapped as
  `Registration verification failed: <server text>` before reaching the
  same alert.
- `conditional_ui.js` inspects `error.name` only for `AbortError`.

## Timeline

## Latest Plan

Map common `DOMException` names to short, actionable messages, keeping
the raw message in `console.error`:

- `InvalidStateError` (registration): this authenticator already has a
  passkey for this account; use another authenticator.
- `NotAllowedError`: cancelled or timed out; no alert, or a short
  notice.
- `SecurityError`: origin / RP ID mismatch (configuration problem).
- Others: keep the current generic message.

### Files

- `oauth2_passkey_axum/static/passkey.js`
- possibly `oauth2_passkey_axum/static/conditional_ui.js`

### Implementation Tasks

- [ ] Registration error mapping
- [ ] Authentication error mapping
- [ ] Check custom-login demos that reuse `passkey.js`

### Verification

- Manual: add a passkey twice on the same authenticator; cancel the
  dialog; confirm messages.
- E2E tests, if they assert on alert text.

## Resolution
