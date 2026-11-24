# Issue: signalAllAcceptedCredentials Sends a userId That Does Not Match the Registered User ID

## Metadata

- ID: 20261124-2345
- Created: 2026-11-24-23-45
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261124-2346` is_discoverable() Uses the Backup Eligibility Flag

## Problem

The bundled JS calls the WebAuthn Signal API
`PublicKeyCredential.signalAllAcceptedCredentials()` with a `userId`
whose bytes differ from the user ID used at registration, so the
authenticator / password manager cannot match it to the stored passkey.

Based on examination of the code on 2026-11-24 (origin/dev 13fde6c):

- The user handle is a base64url string of 32 random bytes
  (`gen_random_string(32)`, `oauth2_passkey/src/utils.rs:44-52`).
- At registration the JS decodes it to bytes for `user.id`:
  `options.user.id = base64URLToUint8Array(userHandle)`
  (`oauth2_passkey_axum/static/passkey.js:355`).
- For `signalAllAcceptedCredentials`, the JS instead UTF-8 encodes the
  base64url string and base64url-encodes that result:
  - `passkey.js:222` (`signalAfterLogin`)
  - `account.js:194`
  - `conditional_ui.js:201`

  `new TextEncoder().encode(user_handle)` yields the bytes of the
  string, not the decoded user ID, so the `userId` sent does not
  identify the registered user.
- `signalCurrentUserDetails` passes `userId: options.userHandle`
  directly (`account.js:471`), which matches the registered user ID.
- `signalUnknownCredential` is scoped by credential ID and is not
  affected.

Effect: the "all accepted credentials" signal is most likely ignored by
the authenticator, so deleted credentials are not pruned from password
managers. No effect on authentication or security checks. Not verified
with a real authenticator.

Found during the 2026-11-24 investigation of adopting `webauthn-rs`.

## Timeline

## Latest Plan

Pass the stored base64url user handle as `userId` unchanged (as
`signalCurrentUserDetails` already does), and remove the `TextEncoder`
conversion at the three call sites.

### Files

- `oauth2_passkey_axum/static/passkey.js`
- `oauth2_passkey_axum/static/account.js`
- `oauth2_passkey_axum/static/conditional_ui.js`

### Implementation Tasks

- [ ] Fix the three call sites (these are the only tracked copies of
      the three JS files)

### Verification

- In a browser with Signal API support (Chrome) and a password manager
  that implements it: delete a passkey, sign in again, and confirm the
  password manager drops the deleted credential.

## Resolution
