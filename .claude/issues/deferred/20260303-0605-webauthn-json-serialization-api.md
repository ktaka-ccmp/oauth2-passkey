# Issue: Adopt WebAuthn Level 3 JSON Serialization API

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260303-0605

## Created: 2026-03-03

## Closed:

## Status: deferred

## Priority: low

## Difficulty: medium

## Description

Migrate from manual base64url-to-ArrayBuffer conversions in JavaScript to the standard WebAuthn Level 3 JSON Serialization API (`parseCreationOptionsFromJSON()` for registration, `parseRequestOptionsFromJSON()` for authentication).

Currently, all JS files manually convert `challenge`, `user.id`, `allowCredentials[].id`, and `excludeCredentials[].id` from base64url strings to `Uint8Array` using a custom `base64URLToUint8Array()` helper. The WebAuthn Level 3 API handles these conversions automatically when the server response conforms to the standard JSON schema.

### Benefits

- Eliminates manual base64url-to-ArrayBuffer conversion code across all JS files
- Standard-compliant JSON format for WebAuthn options
- Future WebAuthn spec additions (new fields requiring ArrayBuffer) work automatically without JS changes
- Better interoperability with other WebAuthn libraries and tools

### Risks

- Requires server-side `RegistrationOptions` struct to conform to the standard `PublicKeyCredentialCreationOptionsJSON` schema (field name changes, e.g., `user.user_handle` -> `user.id`)
- Browser support for Level 3 JSON API needs verification (Chrome/Edge supported, Safari/Firefox may vary)
- Large refactor: all JS files (passkey.js, conditional_ui.js, account.js, promotion_popup.j2) and Rust structs need coordinated changes
- Touches core authentication flows -- risk of regression

### Current Manual Conversion Locations

- `passkey.js`: challenge, user.id, allowCredentials[].id
- `conditional_ui.js`: challenge, allowCredentials[].id
- `promotion_popup.j2`: challenge, user.id, excludeCredentials[].id

## Related Issues

- `20260226-2030` AAGUID-Based Credential Deletion Collision (adds excludeCredentials, another field requiring conversion)

## Approach

Deferred until a major JS refactor or WebAuthn upgrade is needed. The current manual conversion approach is battle-tested and works across all browsers. This is a cleanup/modernization task, not a bug fix.

## Related Files

- `oauth2_passkey/src/passkey/main/types.rs` -- `RegistrationOptions` struct (serde field names need alignment)
- `oauth2_passkey_axum/static/passkey.js` -- registration and authentication JS
- `oauth2_passkey_axum/static/conditional_ui.js` -- conditional UI authentication JS
- `oauth2_passkey_axum/templates/promotion_popup.j2` -- promotion registration JS

## Implementation Tasks

- [ ] Verify browser support for `parseCreationOptionsFromJSON()` and `parseRequestOptionsFromJSON()`
- [ ] Align `RegistrationOptions` struct serde output with `PublicKeyCredentialCreationOptionsJSON` schema
- [ ] Align authentication options with `PublicKeyCredentialRequestOptionsJSON` schema
- [ ] Replace manual conversions in passkey.js with `parseCreationOptionsFromJSON()` / `parseRequestOptionsFromJSON()`
- [ ] Replace manual conversions in conditional_ui.js
- [ ] Replace manual conversions in promotion_popup.j2
- [ ] Add fallback for browsers without Level 3 support (if needed)
- [ ] Update tests

## Decision Log

### 2026-03-03: Created as deferred

- Context: During AAGUID collision issue discussion, considered whether adopting the standard JSON API would simplify excludeCredentials handling
- Decision: Deferred -- current manual conversion works and is universal; migration would be a large refactor for cosmetic improvement
- Reason: Not broken, not urgent. Revisit if a major JS refactor is needed or if new WebAuthn features make manual conversion increasingly burdensome

## Resolution
