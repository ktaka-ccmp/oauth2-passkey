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

## Closed: 2026-05-07

## Status: completed

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

### 2026-05-07T16:04 — current

Reject `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` at config validation,
and change the default (env unset) from `"platform"` to "no
restriction" (= field omitted from JSON). Operators who want to
restrict set `=platform` or `=cross-platform` explicitly. This is
**Option A** in the 2026-05-07 followup decision; **Option B**
(accept `=none` and translate internally) is recorded as superseded
just below.

Concrete edits:

1. **`oauth2_passkey/src/passkey/main/types.rs:39-44`** — change
   `AuthenticatorSelection.authenticator_attachment` from `String` to
   `Option<String>`, and add
   `#[serde(skip_serializing_if = "Option::is_none")]`.

2. **`oauth2_passkey/src/passkey/config.rs:50-62`** — change the
   static type from `LazyLock<String>` to `LazyLock<Option<String>>`.
   - `Err(_)` (env unset) → `None` (default = no restriction).
   - `Ok("platform")` → `Some("platform".to_string())`.
   - `Ok("cross-platform")` → `Some("cross-platform".to_string())`.
   - **Remove** the `"none"` arm. Update the panic message to list
     valid values as `platform, cross-platform` only and to mention
     "to allow either, leave the variable unset".

3. **`oauth2_passkey/src/passkey/main/register.rs:193`** — change
   `PASSKEY_AUTHENTICATOR_ATTACHMENT.to_string()` to
   `PASSKEY_AUTHENTICATOR_ATTACHMENT.clone()`.

4. **`oauth2_passkey/src/passkey/config/tests.rs`** — update existing
   `=platform` / `=cross-platform` assertions for the new
   `Option<String>` type. **Replace** the `=none` test case with a
   panic-on-`=none` assertion. Add a default-unset test confirming
   the static is `None` when the env var is not set.

5. **`dot.env.example`** — replace any
   `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` line with a comment
   explaining the variable is optional and defaults to "either".

6. **`CHANGELOG.md`** — add an unreleased entry noting (a)
   `=none` is no longer accepted (unset for the same effective
   behavior) and (b) the default changed from `=platform` to
   unrestricted.

Other passkey enum env vars (`PASSKEY_ATTESTATION`,
`PASSKEY_RESIDENT_KEY`, `PASSKEY_USER_VERIFICATION`) do not have the
same problem — none of them emit a non-spec string for any input.
Scope is limited to `authenticator_attachment`.

### 2026-05-07T15:44 — superseded (see Decision Log 2026-05-07T16:04)

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

### 2026-03-31 — superseded (see Decision Log 2026-05-07T15:44)

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

- [x] Change `AuthenticatorSelection.authenticator_attachment` to
      `Option<String>` with
      `#[serde(skip_serializing_if = "Option::is_none")]`
- [x] Change `PASSKEY_AUTHENTICATOR_ATTACHMENT` static type to
      `LazyLock<Option<String>>`; remove the `"none"` arm; default
      `Err(_)` to `None`; update panic message
- [x] Update `register.rs:193` from `.to_string()` to `.clone()`
- [x] Update / replace affected tests in `passkey/config/tests.rs`
      (panic-on-`=none`, default unset → `None`, `=platform` /
      `=cross-platform` → `Some(...)`)
- [x] Update `dot.env.example` to remove the
      `PASSKEY_AUTHENTICATOR_ATTACHMENT=none` example and document
      the new "unset = either" semantics
- [x] Add `CHANGELOG.md` entry noting the breaking change
      (`=none` rejected; default shifts from `=platform` to
      unrestricted)
- [x] `cargo fmt --all && cargo clippy --all-targets --all-features
      && cargo test`
- [x] Manual verification: env unset → JSON has no
      `authenticatorAttachment` field; `=platform` / `=cross-platform`
      → field present with that value; `=none` → app panics at
      startup with new error message

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-05-07T15:44: Approach refined for compile-correctness; spec claim softened

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

### 2026-05-07T16:04: Chose Option A (reject `=none`) over Option B (translate internally)

The 15:44 Approach kept accepting `PASSKEY_AUTHENTICATOR_ATTACHMENT=none`
at the env layer and translating it to `Option::None` internally so
that serde would omit the field. On reflection this is roundabout —
the env value (`"none"`) and the JSON value (omitted) live in
different value systems, with the config layer doing a silent shift.

Two designs considered in the 16:04 review:

- **Option A (chosen)**: reject `=none` at config validation. Make
  the env unset case (`Err(_)`) the way to express "no restriction"
  by returning `None`. Default shifts from `=platform` to
  unrestricted. To force platform-only, operators must set
  `=platform` explicitly.
- **Option B (15:44 Approach above)**: keep accepting `=none`,
  translate to `None` internally, omit field. Default unchanged at
  `=platform`.

Option A reasons:

- **Single value system**: env value matches what gets sent (or
  matches "field absent" via "unset"). No translation layer to
  remember.
- **Spec alignment**: "no restriction" in WebAuthn is "field absent",
  so the env being unset (= absent) maps to the JSON being absent.
- **Permissive default**: most passkey-supporting apps want either
  attachment, so unrestricted is a friendlier default than
  platform-only for new users.
- **Smaller code**: the match has only the two valid arms plus the
  panic; no special `"none"` arm.

Option A trade-offs accepted:

- **Breaking change for `=none` users**: they must unset the variable
  to get the same effective behavior. Pre-1.0 (project at v0.5.x),
  CHANGELOG covers it.
- **Default shift from `=platform` to unrestricted**: pre-existing
  operators relying on the default now get either attachment by
  default. This direction is permissive (security-wise it removes
  a forced restriction) — appropriate for most apps; operators with
  specific requirements can re-add `=platform` explicitly.

## Resolution

Implemented Option A on branch `fix-passkey-attachment-none-omit`.

- `b310ff4` `fix(passkey)!: reject PASSKEY_AUTHENTICATOR_ATTACHMENT=none, default to omit`
  — `AuthenticatorSelection.authenticator_attachment` is now
  `Option<String>` with `#[serde(skip_serializing_if = "Option::is_none")]`;
  `PASSKEY_AUTHENTICATOR_ATTACHMENT` static is `LazyLock<Option<String>>`
  with the `"none"` arm removed and `Err(_)` returning `None`;
  `register.rs:193` uses `.clone()`; tests updated and a
  panic-on-`=none` test added; `dot.env.example` comment refreshed.
- `90d7983` `docs(changelog): note breaking change to PASSKEY_AUTHENTICATOR_ATTACHMENT`
  — appended Breaking bullet under `[0.5.1-dev]` / `### Changed`.

Verification:
- `cargo fmt --all`, `cargo clippy --all-targets --all-features`,
  `cargo test --lib` all green (693 + 71 lib tests pass).
- Targeted `passkey::config::tests::test_passkey_authenticator_attachment*`
  (4 tests) all pass: rejects-invalid, accepts-valid, rejects-none
  (new), defaults-to-none (renamed from `_to_platform`).
- Manual verification noted in the manual-verification checkbox
  above.
