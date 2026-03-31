---
id: 20260331-1517
title: "PASSKEY_AUTHENTICATOR_ATTACHMENT=none sends non-standard string instead of omitting field"
status: open
priority: low
created: 2026-03-31
---

## Description

When `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` is set, the config maps it to the string `"None"`,
which is then serialized as `authenticatorAttachment: "None"` in the WebAuthn `RegistrationOptions` JSON.

The WebAuthn spec defines `authenticatorAttachment` as an enum with only two valid values:
`"platform"` and `"cross-platform"`. To allow both, the field should be **omitted entirely** from
the JSON, not set to a non-standard string.

## Root Cause

In `oauth2_passkey/src/passkey/config.rs`:

```rust
"none" => "None".to_string(),
```

And in `oauth2_passkey/src/passkey/main/types.rs`, `AuthenticatorSelection.authenticator_attachment`
is `String` (not `Option<String>`), so it is always serialized.

## Fix Required

1. Change `authenticator_attachment` in `AuthenticatorSelection` to `Option<String>`
2. Add `#[serde(skip_serializing_if = "Option::is_none")]`
3. In config, return `None` (the Rust `Option`) when env var is `"none"`

## Current Impact

Low. Browsers are expected to ignore unknown enum values per the WebAuthn spec and treat the
field as if it were absent, allowing both platform and cross-platform authenticators.
The demo site uses `none` as a workaround and appears to work correctly in practice.
