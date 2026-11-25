# Issue: Review the Default PASSKEY_USER_VERIFICATION=discouraged

## Metadata

- ID: 20261125-1003
- Created: 2026-11-25-10-03
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20261125-1002` Registration Checks rpIdHash, UP and UV Only for the "none" Attestation Format

## Problem

`PASSKEY_USER_VERIFICATION` defaults to `discouraged`. Sign-in uses
discoverable credentials without a username or password, so with this
default a passkey sign-in is possession of the authenticator only.
Current guidance and the spec default are `preferred`, and the
library's own production guide recommends `required` or `preferred`.
The default was chosen deliberately; this issue is to decide whether it
still fits.

Raised by an external review (Gemini via `agy`, 2026-11-25); facts
below were checked on 2026-11-25 (origin/dev 13fde6c and the sources
listed).

Current behavior:

- Default `discouraged` (`oauth2_passkey/src/passkey/config.rs:93-105`),
  sent in both registration and authentication options
  (`register.rs:196`, `auth.rs:84`); `conditional_ui.js:115` passes the
  server value through.
- The server checks the UV flag only when the setting is `required`
  (`types.rs:383-388` for authentication; for registration only in the
  `none` verifier, see `20261125-1002`).
- Resident key is required by default and the attachment is unset
  (any authenticator, including roaming security keys)
  (`config.rs:55-91`).

Documentation:

- `docs/src/integration/configuration.md:283-296`,
  `docs/src/integration/passkey.md:120,216,660`, `dot.env.example:320-321`
  document the default `discouraged`.
- `docs/src/security/production.md:97-103` recommends `required` (high
  security) or `preferred` for production.
- `demo-live/README.md:102` and `demo-live/env.cloud-run.yaml:65` set
  `discouraged` ("Skips biometric prompt for faster UX");
  `demo-cross-origin/.env.example:95` also sets it.

History:

- The value comes from the first passkey code (`b76f528`, 2025-01-29),
  with the comment: "user verification doesn't necessarily improve
  security, because the attacker can change PIN once the password
  manager is compromised". At that time the attachment was fixed to
  `platform` ("We prefer platform authenticators i.e. to use Google's
  password manager"). The attachment default is now unset.

External guidance (fetched 2026-11-25):

- WebAuthn L3: the IDL default of `userVerification` is `"preferred"`
  in both `AuthenticatorSelectionCriteria` and
  `PublicKeyCredentialRequestOptions`. Registration step: "If the
  Relying Party requires user verification for this registration,
  verify that the UV bit ... is set"; authentication: "User
  verification SHOULD be required if, and only if,
  pkOptions.userVerification is set to required".
- passkeys.dev, "Bootstrapping an account on the web": the sample uses
  `userVerification: "preferred"`; "A note about user verification:
  This guidance sets userVerification to preferred, meaning that user
  verification will be attempted when possible."
- web.dev, "Create a passkey for passwordless logins": "The default is
  "preferred" ... Set this to "preferred" or omit the property."
  web.dev, "Sign in with a passkey through form autofill": "The default
  and recommended value is "preferred"."
- Google Identity server-side guides use `userVerification: 'preferred'`
  with `requireUserVerification: false` in the SimpleWebAuthn samples.
- `webauthn-rs-proto` 0.6.2 names the variant `Discouraged_DO_NOT_USE`
  ("Many CTAP devices will attempt UV during registration but not
  authentication leading to user confusion",
  `src/options.rs:64-67`); its high-level passkey API fixes
  `Required`.

Points for the decision:

- For synced platform passkeys, the original argument (a compromised
  password manager defeats UV) still applies, and platforms often
  perform UV anyway (not verified here).
- For roaming security keys, which the current default allows, or for
  an unlocked shared device, `discouraged` lets a touch sign in.
- `preferred` keeps working on devices without UV; `required` can lock
  out such devices.
- Changing the default changes behavior for deployments that rely on
  it, so it needs a CHANGELOG entry when released.
- Optional: record whether UV was performed at registration and reject
  later sign-ins without UV for that credential (the approach
  `webauthn-rs-core` uses for `Preferred`).

## Timeline

## Latest Plan

Decide the default (`preferred` is the option suggested by the
sources above). If changed: update `config.rs`, the docs and examples
listed above, and the demo settings if they should follow; add tests
for the default value.

### Files

- `oauth2_passkey/src/passkey/config.rs`
- `docs/src/integration/{configuration,passkey}.md`,
  `docs/src/security/production.md`, `dot.env.example`
- `demo-live/{README.md,env.cloud-run.yaml}`, `demo-cross-origin/.env.example`

### Implementation Tasks

- [ ] Decide the default
- [ ] Update code, docs, examples
- [ ] (Optional) track UV at registration

### Verification

- Registration and sign-in on the demo with a platform authenticator
  and a security key, with the new default.

## Resolution
