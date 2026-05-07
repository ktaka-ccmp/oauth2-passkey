# Issue: PASSKEY_AUTHENTICATOR_ATTACHMENT=none sends non-standard string instead of omitting field

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260331-1517

## Created: 2026-03-31-15-17

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

When `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` is set, the config maps it
to the string `"None"` (`oauth2_passkey/src/passkey/config.rs:56`),
which is then serialized as `authenticatorAttachment: "None"` in the
WebAuthn `RegistrationOptions` JSON sent from
`oauth2_passkey/src/passkey/main/register.rs:193` to the browser.

The WebAuthn spec defines `AuthenticatorAttachment` as a WebIDL `enum`
with only two valid values: `"platform"` and `"cross-platform"`. The
`authenticatorSelection.authenticatorAttachment` dictionary field is
optional — to allow both attachment types, the field should be
**omitted entirely** from the JSON, not set to a non-standard string.

`AuthenticatorSelection.authenticator_attachment` is currently typed
`String` (`oauth2_passkey/src/passkey/main/types.rs:40`), so it is
always serialized — there is no way to omit it short of changing the
type.

### Current impact

Low. The demo site uses `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` as a
workaround and works correctly in practice — modern browsers tolerate
the unknown enum value `"None"` and treat the field as absent. This is
empirical browser leniency, not a WebIDL guarantee: per WebIDL, an
invalid enum string in a dictionary field should produce a
`TypeError` at dictionary construction time.

## Related Issues

- (none currently tracked)

## Approach

### 2026-05-07 — current

The original 2026-03-31 plan names the right three ideas
(`Option<String>` field, `skip_serializing_if`, return `None` from
config) but does not enumerate the type-change ripples. Verbatim
application would not compile. Detailed plan with the connective
tissue:

1. **`oauth2_passkey/src/passkey/main/types.rs:39-44`** — change
   `AuthenticatorSelection.authenticator_attachment` from `String` to
   `Option<String>`, and add
   `#[serde(skip_serializing_if = "Option::is_none")]`.

2. **`oauth2_passkey/src/passkey/config.rs:50-62`** — change the
   static type from `LazyLock<String>` to `LazyLock<Option<String>>`.
   Wrap each `Ok` match arm in `Some(...)`, change the `"none"` arm
   to `None`, and wrap the default `"platform"` (Err arm) in
   `Some("platform".to_string())`.

3. **`oauth2_passkey/src/passkey/main/register.rs:193`** — change
   `PASSKEY_AUTHENTICATOR_ATTACHMENT.to_string()` to
   `PASSKEY_AUTHENTICATOR_ATTACHMENT.clone()`. The previous form
   would now stringify the entire `Option` (e.g. `"Some(\"platform\")"`)
   rather than the inner string.

4. **`oauth2_passkey/src/passkey/config/tests.rs`** — update
   assertions on the static (around L121 and L318) from
   `*PASSKEY_AUTHENTICATOR_ATTACHMENT == "platform"` to
   `*PASSKEY_AUTHENTICATOR_ATTACHMENT == Some("platform".to_string())`
   (or `.as_deref() == Some("platform")`).

The other passkey enum env vars (`PASSKEY_ATTESTATION`,
`PASSKEY_RESIDENT_KEY`, `PASSKEY_USER_VERIFICATION`) do not have the
same problem — none of them emit a non-spec string for any input.
Scope is limited to `authenticator_attachment`.

### 2026-03-31 — superseded (see Decision Log 2026-05-07)

1. Change `authenticator_attachment` in `AuthenticatorSelection` to
   `Option<String>`
2. Add `#[serde(skip_serializing_if = "Option::is_none")]`
3. In config, return `None` (the Rust `Option`) when env var is
   `"none"`

## Related Files

- `oauth2_passkey/src/passkey/config.rs` (static + valid value list)
- `oauth2_passkey/src/passkey/main/types.rs` (`AuthenticatorSelection` struct)
- `oauth2_passkey/src/passkey/main/register.rs` (call site at L193)
- `oauth2_passkey/src/passkey/config/tests.rs` (assertions on static)

## Implementation Tasks

- [ ] Change `AuthenticatorSelection.authenticator_attachment` to
      `Option<String>` with
      `#[serde(skip_serializing_if = "Option::is_none")]`
- [ ] Change `PASSKEY_AUTHENTICATOR_ATTACHMENT` static type to
      `LazyLock<Option<String>>`; wrap arms accordingly
- [ ] Update `register.rs:193` from `.to_string()` to `.clone()`
- [ ] Update affected assertions in `passkey/config/tests.rs`
- [ ] `cargo fmt --all && cargo clippy --all-targets --all-features
      && cargo test`
- [ ] Manual verification: `PASSKEY_AUTHENTICATOR_ATTACHMENT=none`
      → JSON has no `authenticatorAttachment` field
- [ ] Manual regression: default and `=platform` /
      `=cross-platform` → JSON contains the literal value

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-05-07: Approach refined for compile-correctness; spec claim softened

End-to-end review of the original 2026-03-31 plan found two issues:

- **Plan was underspecified**: the three steps named are correct ideas
  but cannot be applied verbatim. The config static's type changes
  from `LazyLock<String>` to `LazyLock<Option<String>>`, which ripples
  to every `Ok` arm, the default `Err` arm, the call site at
  `register.rs:193`, and the assertions in `config/tests.rs`. Without
  these adjacent edits the change does not compile. The current
  Approach enumerates them.

- **Spec wording was too strong**: the original Description said
  "browsers are expected to ignore unknown enum values per the
  WebAuthn spec". Per WebIDL, an invalid enum string in a dictionary
  field should produce `TypeError` at construction. The fact that
  `"None"` works in practice is browser leniency, not a WebIDL
  guarantee. Description and Current impact are reworded to make
  this distinction clear.

Cross-checked the other passkey enum env vars
(`PASSKEY_ATTESTATION`, `PASSKEY_RESIDENT_KEY`,
`PASSKEY_USER_VERIFICATION`) for the same pattern — none have it.
Scope stays limited to `authenticator_attachment`.

## Resolution

<!-- To be filled in when resolved -->
