# Issue: Introduce `ProviderName` newtype for stringly-typed provider identifiers

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260422-2055

## Created: 2026-04-22-20-55

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Throughout the OAuth2 module, `provider_name` is passed around as
`&str` / `&'static str` (stringly-typed). Any string typechecks — the
compiler cannot enforce that a value tagged "provider name" was
actually produced by a validated, registered provider. This surfaces
in multiple places:

- `ProviderConfig.provider_name: &'static str`
- `OAuth2Account.provider: String` (database column)
- Handler / router path parameters
- Log and metrics labels

Introducing a newtype, e.g.

```rust
pub struct ProviderName(&'static str);
```

with only validated constructors (`ProviderKind::as_name()`,
`ProviderConfig::name()`, `from_env_or_default(...)`) would make
invalid values unrepresentable at the type level. This addresses the
type-safety concern raised during planning of `20260422-1552`: passing
primitives like `(provider_name: &str, strict_display_claims: bool)`
accumulates and loses pair-consistency guarantees as flags grow;
adopting `&ProviderConfig` mitigates most internal call sites, but the
underlying `provider_name` identifier remains a `&str` at the type
boundary.

### Motivation

- **Code health**: removes a stringly-typed pattern that will accrete
  over time.
- **Type safety at boundaries**: validated-at-construction invariants
  that the compiler enforces going forward.
- **Consistency with `ProviderKind`**: we already have a validated
  enum for the "which provider" axis; the flat name string should be
  derived from that rather than flowing independently.

### Note on scope relative to `20260422-1552`

The claim-mismatch PR (`20260422-1552`) already switches
`oauth2_account_from_idinfo_and_userinfo` and
`oauth2_account_from_idinfo` to take `&ProviderConfig`. That narrows
the surface where `provider_name: &str` is passed around. What remains
— and what this issue addresses — is the `&str` / `String` field on
`ProviderConfig` itself and the storage-side `String` on
`OAuth2Account.provider`. The newtype refactor is tracked separately
because it touches storage, routing, and potentially the public API
surface, too broad to bundle with the claim-mismatch PR.

## Related Issues

- `.claude/issues/open/20260422-1552-detect-claim-mismatch-idinfo-userinfo.md`
  — where `&ProviderConfig` passing was adopted and the newtype idea was
  extracted as follow-up
- `.claude/issues/completed/20260420-1511-add-generic-oidc-provider.md`
  — where the current `provider_name: &'static str` pattern was set up
  for the Generic OIDC slot work

## Approach

Sketch (to be refined when the work is scheduled):

1. Introduce `ProviderName` in `oauth2/provider.rs`
   (e.g. `#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize,
   Deserialize)] pub struct ProviderName(&'static str);`) with
   validated-construction paths only (`ProviderKind::as_name()` and
   `ProviderConfig::name()`).
2. Replace `provider_name: &'static str` on `ProviderConfig` with
   `ProviderName`.
3. Replace `&str`-typed function params with `ProviderName` or derive
   via `ctx: &ProviderConfig`.
4. Ripple-update storage rows (`OAuth2Account.provider`), router /
   handler path parameters, audit-log labels.
5. Implement `Display` / `AsRef<str>` for ergonomics at the boundary
   (URLs, logs, DB serialization).
6. Consider whether a separate `ProviderSlug` type is warranted for
   raw URL-safe identifiers vs. a `DisplayName` for human-facing text.

## Related Files

Estimated scope — to be confirmed during execution:

- `oauth2_passkey/src/oauth2/provider.rs` — newtype declaration,
  `ProviderConfig` field, `ProviderKind::as_name()` helper
- `oauth2_passkey/src/oauth2/types.rs` — `OAuth2Account.provider`
- `oauth2_passkey/src/coordination/oauth2.rs` — handler parameter types
- `oauth2_passkey_axum/src/` — router path extractors, handler signatures
- `oauth2_passkey/src/storage/` — DB (de)serialization of `provider`
  column
- Tests across the above

## Implementation Tasks

- [ ] Decide newtype shape (single `ProviderName` vs. split
  `ProviderName` + `ProviderSlug`)
- [ ] Introduce type and validated constructors; cover with unit tests
- [ ] Replace `&'static str` / `&str` usages inside `oauth2_passkey`
- [ ] Ripple storage column (de)serialization — verify wire format
  unchanged to avoid migration
- [ ] Ripple `oauth2_passkey_axum` router / handler types
- [ ] `cargo fmt --all` / `cargo clippy --all-targets --all-features`
      / `cargo test` — full green
- [ ] Verify no public API break (or document it in CHANGELOG)
- [ ] E2E smoke test against one named and one Custom provider

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-22: Extracted as follow-up from `20260422-1552`

- Context: While planning claim-mismatch detection, we debated whether
  to pass `provider_name: &str` as a primitive argument or bundle
  config via `&ProviderConfig`. Selected `&ProviderConfig` for the
  narrow builder signatures. That addresses pair-consistency within
  the function but does not fix the root stringly-typed pattern on
  `ProviderConfig.provider_name` / `OAuth2Account.provider`.
- Decision: File this as a separate issue rather than expanding the
  `20260422-1552` PR, because the newtype touches storage, routing,
  and public API surface. The claim-mismatch PR's scope stays tight.
- Reason: Code-health refactors of this breadth deserve their own
  discussion, review, and E2E validation window. Bundling them
  dilutes both reviews.

## Resolution

(pending)
