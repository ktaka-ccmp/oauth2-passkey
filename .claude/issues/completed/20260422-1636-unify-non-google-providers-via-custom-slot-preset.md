# Issue: Unify non-Google providers under Custom slot with presets

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Motivation and Timing](#motivation-and-timing)
- [Design](#design)
- [Migration](#migration)
- [Trade-offs Considered](#trade-offs-considered)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260422-1636

## Created: 2026-04-22-16-36

## Closed: 2026-04-23-01-36

## Status: completed

## Priority: medium-high

## Difficulty: medium

## Description

Collapse the parallel "named provider" path (`Auth0`, `Keycloak`,
`Entra`) into the existing Custom OIDC slot mechanism by adding a
`PRESET` concept. Google stays named due to library-side features
(FedCM, Google-specific query string, `hd` claim handling) that are
not expressible as a plain OIDC provider. All other providers become
Custom slots, optionally pre-populated by a preset that fills in
display name, provider name, icon slug, button colors, and any
library-side quirks (e.g. additional allowed origins).

Outcome:

- `ProviderKind::{Auth0, Keycloak, Entra}` variants removed
- `AUTH0_PROVIDER` / `KEYCLOAK_PROVIDER` / `ENTRA_PROVIDER` LazyLock
  statics removed
- `OAUTH2_AUTH0_*` / `OAUTH2_KEYCLOAK_*` / `OAUTH2_ENTRA_*` env vars
  removed
- Operators enable Auth0 / Keycloak / Entra via a Custom slot plus
  `OAUTH2_CUSTOM{N}_PRESET={auth0|keycloak|entra}`

## Related Issues

- `20260420-1511` Add Generic OIDC Provider Slots — shipped the
  Custom slot infrastructure this issue consolidates into
- `20260226-2019` Finalize Public API for 1.0 Release — this change
  should land **before** the 1.0 API freeze; reshaping `ProviderKind`
  after 1.0 is a breaking-change hazard

## Motivation and Timing

### Why unify

1. **Asymmetry removal.** The current named list (Google, Auth0,
   Keycloak, Entra) is somewhat arbitrary given the Custom slot path
   supports arbitrary OIDC IdPs. Okta, Authentik, and Zitadel were
   all verified through Custom slots with the same quality as the
   named providers; there is no principled reason Auth0 / Keycloak /
   Entra should be named while those are not.
2. **Code-surface reduction.** Three named-provider LazyLock statics,
   three `ProviderKind` variants, three doc sections, and three sets
   of env var names collapse into the existing Custom slot
   infrastructure. Fewer things to maintain, test, and version.
3. **Operator consistency.** One configuration pattern for every
   non-Google IdP.
4. **Custom slot code path is already proven.** PR #316 validated the
   path end-to-end against 5 IdPs (Zitadel v2/v4, Ory Hydra,
   Authentik, Okta). Routing Auth0 / Keycloak / Entra through the
   same path carries no incremental risk.

### Why timing matters

As of 2026-04-22, `v0.5.0` (released 2026-03-23) ships **Google
only** — Auth0, Keycloak, Entra, and the Custom slot feature itself
are all on `feature/generic-oidc-provider-slots`, unmerged and
unreleased. That means:

- No downstream crates.io user has `OAUTH2_AUTH0_*` /
  `OAUTH2_KEYCLOAK_*` / `OAUTH2_ENTRA_*` in production.
- No production database has `provider='auth0'` / `'keycloak'` /
  `'entra'` rows from a released binary.

Performing this unification now is therefore **not a breaking
change** — it is a pre-release architectural choice. After the 1.0
API freeze and operator adoption, the same unification becomes a
breaking migration affecting env vars, DB rows, and downstream code.
The cheap moment is now.

### Scope out

- Google stays named. FedCM, `access_type=online`, `hd` claim
  handling, and Google-specific query-string formatting are
  library-side features that cannot be expressed as a generic OIDC
  preset.

## Design

### Preset definition

A preset is a compile-time record that provides defaults for every
optional Custom slot field, plus library-side quirks that are not
exposed as env vars on the bare Custom slot today:

```rust
pub(crate) struct ProviderPreset {
    /// Human-readable label for login buttons.
    display_name: &'static str,
    /// Default URL provider name (operator can override).
    provider_name: &'static str,
    /// SVG icon basename under `/icons/{slug}.svg`.
    icon_slug: &'static str,
    /// Default button background color.
    button_color: &'static str,
    /// Default button hover color.
    button_hover_color: &'static str,
    /// CSS variable suffix.
    css_var_suffix: &'static str,
    /// Additional origins to accept in `validate_origin` beyond the
    /// authorization endpoint's origin (e.g. `login.live.com` for
    /// Entra personal accounts).
    additional_allowed_origins: &'static [&'static str],
}

const AUTH0_PRESET: ProviderPreset = ProviderPreset {
    display_name: "Auth0",
    provider_name: "auth0",
    icon_slug: "auth0",
    button_color: "#eb5424",
    button_hover_color: "#c7431f",
    css_var_suffix: "auth0",
    additional_allowed_origins: &[],
};

const KEYCLOAK_PRESET: ProviderPreset = ...;
const ENTRA_PRESET: ProviderPreset = ProviderPreset {
    // ...
    additional_allowed_origins: &["https://login.live.com"],
};
```

### Env var shape

Most operators write three env vars (matching today's named-provider
UX):

```bash
OAUTH2_CUSTOM1_PRESET=auth0
OAUTH2_CUSTOM1_CLIENT_ID=<from Auth0>
OAUTH2_CUSTOM1_CLIENT_SECRET=<from Auth0>
OAUTH2_CUSTOM1_ISSUER_URL=https://dev-xxx.auth0.com
```

Preset fills in `DISPLAY_NAME`, `NAME`, `ICON_SLUG`,
`BUTTON_COLOR`, `BUTTON_HOVER_COLOR`, and `additional_allowed_origins`.

Any individual preset field can be overridden explicitly:

```bash
OAUTH2_CUSTOM1_PRESET=auth0
OAUTH2_CUSTOM1_CLIENT_ID=...
OAUTH2_CUSTOM1_CLIENT_SECRET=...
OAUTH2_CUSTOM1_ISSUER_URL=...
OAUTH2_CUSTOM1_NAME=company-sso   # override preset default "auth0"
OAUTH2_CUSTOM1_BUTTON_COLOR='#ff0000'
OAUTH2_CUSTOM1_DISPLAY_NAME='Company SSO'
```

Plain Custom slots (no preset) keep current behavior: operator must
supply `DISPLAY_NAME` and `NAME`; button colors default to
neutral gray; `icon_slug` defaults to `openid`.

### New / changed fields

- Add `OAUTH2_CUSTOM{N}_PRESET` env var. Valid values:
  `auth0` | `keycloak` | `entra`. Invalid value → fail at init with
  `OAuth2Error::Validation` listing accepted options.
- Add `OAUTH2_CUSTOM{N}_ICON_SLUG` env var (previously deferred in
  `20260420-1511`). Needed so operators can override an `icon_slug`
  assigned by preset, or pick a non-preset well-known slug.
- `build_custom_provider` consults the preset (if set) before
  falling back to bare Custom slot defaults for each field.

### `validate_custom_slots` extensions

- Verify preset value is one of the allowed keywords.
- `additional_allowed_origins` from the preset is applied to the
  resolved `ProviderConfig` and exercised by the existing origin
  validator. No new operator env var surface.

## Migration

### Breaking changes removed by this issue

- `OAUTH2_AUTH0_CLIENT_ID` / `_CLIENT_SECRET` / `_ISSUER_URL` /
  `_RESPONSE_MODE` / `_SCOPE` — removed, replaced by
  `OAUTH2_CUSTOM{N}_*` with `PRESET=auth0`.
- Same for `OAUTH2_KEYCLOAK_*` and `OAUTH2_ENTRA_*`.

### Is this actually breaking?

No, for external consumers. See [Motivation and Timing](#motivation-and-timing):
Auth0 / Keycloak / Entra have never been released via crates.io.
Downstream users of `v0.5.x` have Google only.

For internal `.env` files in this repo (e.g. `.env`), migration is a
mechanical edit — swap prefixes and add `PRESET=...`. The demo
applications (`demo-*/.env*`) and test harness (`test_utils`) will
be updated in the same PR.

### CHANGELOG / release notes framing

Per project memory `feedback_changelog_timing`: WIP code is not a
released API. This change produces no CHANGELOG "Breaking" entry
because the removed env vars were never in a released version. The
PR description should document the consolidation for reviewers, but
the public changelog for the version that ships this (likely
`0.6.0-dev` → `0.6.0`) will describe only the landed feature:
"Custom OIDC slots with presets for Auth0, Keycloak, Entra".

## Trade-offs Considered

### Alternative 1: keep named, extend Custom for operators who want more

Rejected. Leaves two parallel code paths, same tests duplicated,
same asymmetry. The only reason to keep this split is to preserve
the 3-env-var UX, which the preset system already provides.

### Alternative 2: delete named without adding preset — operators write 5 env vars

Rejected. `DISPLAY_NAME` / `NAME` / `BUTTON_COLOR` /
`BUTTON_HOVER_COLOR` are the same for every operator using Auth0.
Forcing each of them to re-type these is pure UX regression for no
library benefit.

### Alternative 3: unify everything including Google

Rejected. FedCM is called out in `coordination/oauth2.rs:494` as
"currently Google-only" and built on a separate `validate_fedcm_token`
+ `prepare_fedcm_nonce` path. Google also has `access_type=online`
in its query string (not in the OIDC spec) and the `hd` claim.
These are library-level, not library-config-level, features. Expressing
them as a preset would leak provider-specific logic into the preset
schema, which defeats the unification purpose.

## Related Files

### To modify

- `oauth2_passkey/src/oauth2/provider.rs` — remove `Auth0`,
  `Keycloak`, `Entra` variants from `ProviderKind`; remove
  `AUTH0_PROVIDER` / `KEYCLOAK_PROVIDER` / `ENTRA_PROVIDER`
  LazyLocks; add `ProviderPreset` + three `const *_PRESET`s; extend
  `build_custom_provider` to consult preset; extend
  `optional_env_contract` + `validate_custom_slots` for PRESET and
  ICON_SLUG env vars
- `oauth2_passkey/src/oauth2/provider/tests.rs` — add preset
  resolution tests, preset override tests, invalid-preset-value
  rejection test; remove / adapt tests that exercise named providers
- `oauth2_passkey/src/oauth2/config.rs` — `enabled_providers` /
  `provider_info` already read from `ProviderConfig`; adjust
  iteration to reflect slimmer `ProviderKind::ALL`
- `oauth2_passkey/src/oauth2/mod.rs` — remove named-provider
  re-exports if any leak out
- `oauth2_passkey/src/coordination/oauth2.rs` — FedCM section that
  does `provider_for(ProviderKind::Google)` is fine; no changes
- `oauth2_passkey_axum/src/oauth2.rs` — `ProviderView` /
  `enabled_provider_views` / `custom_css_vars_block` already
  delegate to `enabled_providers`; icon handling needs to honor the
  preset-supplied `icon_slug` (already uses `ProviderInfo.icon_slug`)

### To update

- `dot.env.example` — replace dedicated `OAUTH2_AUTH0_*` /
  `OAUTH2_KEYCLOAK_*` / `OAUTH2_ENTRA_*` blocks with Custom slot
  examples that use PRESET
- `docs/src/guides/auth0.md` / `keycloak.md` / `entra.md` — rewrite
  (or deprecate in favor of a single consolidated guide) so examples
  show `OAUTH2_CUSTOM{N}_PRESET=...`
- `docs/src/guides/generic-oidc.md` — document the preset system;
  cross-link from Auth0 / Keycloak / Entra pages
- `docs/src/SUMMARY.md` — adjust entries if individual guides are
  consolidated
- Demo `.env.*` under `demo-*/`, `test_utils` fixtures — swap
  prefixes; regenerate any Cargo.lock drift

### To remove

- Any tests hardcoded to `ProviderKind::Auth0` / `::Keycloak` /
  `::Entra` that no longer compile

## Implementation Tasks

- [x] Define `ProviderPreset` struct and the 3 consts
      (`AUTH0_PRESET`, `KEYCLOAK_PRESET`, `ENTRA_PRESET`)
- [x] Remove `Auth0` / `Keycloak` / `Entra` from `ProviderKind`;
      delete the three matching `LazyLock` statics and their
      `provider_for` arms
- [x] Extend `build_custom_provider` to consult the preset (via a
      new `OAUTH2_CUSTOM{N}_PRESET` env var lookup) and merge preset
      defaults with explicit env-var overrides
- [x] Add `OAUTH2_CUSTOM{N}_ICON_SLUG` env var support (was
      deferred in `20260420-1511`)
- [x] Extend `optional_env_contract` / `validate_custom_slots` to
      validate PRESET values and ICON_SLUG shape
- [x] Unit tests:
      - preset resolves expected defaults
      - preset override works per field
      - invalid PRESET value rejected at init
      - `additional_allowed_origins` from preset applied to origin
        validator
- [x] Update `.env` / `.env.example` / `demo-*/.env*` to use the
      unified form
- [x] Update docs (`auth0.md`, `keycloak.md`, `entra.md`,
      `generic-oidc.md`, `SUMMARY.md`)
- [x] `cargo fmt --all` / `cargo clippy --all-targets --all-features`
      / `cargo test`
- [x] E2E regression:
      - Google (named, unchanged) — login + demo flows
      - Auth0 via `PRESET=auth0`
      - Keycloak via `PRESET=keycloak`
      - Entra (work/school + personal) via `PRESET=entra`
      - At least one unchanged non-preset Custom slot (Zitadel /
        Authentik / Okta) — verify no regression in the bare path

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-22: File issue while pre-release

- Context: discussion during the PR #316 follow-up review round.
  Question raised: "could we eventually route everything except
  Google through Custom OIDC?" Initial response leaned conservative
  (breaking change, migration cost). On confirming that v0.5.0
  shipped Google only and all non-Google providers live only on the
  unmerged `feature/generic-oidc-provider-slots` branch, the
  calculus flipped — this is a pre-release cleanup window, not a
  breaking migration.
- Decision: file this issue now so the consolidation lands before
  the 1.0 API freeze (`20260226-2019`). Do not bundle with PR #316:
  let that PR merge as-is to keep the review focus on "add Custom
  slots", and handle the consolidation as a standalone follow-up PR.
- Reason: post-1.0, removing `ProviderKind::Auth0` / `::Keycloak` /
  `::Entra` is a hard breaking change. Pre-1.0 and pre-release, it
  is a straightforward refactor with no external blast radius.

## Resolution

Implemented in PR #319 (`refactor/provider-preset-unification`) across
commits 1–5 (2026-04-22/23):

- `ProviderPreset` struct + `AUTH0_PRESET` / `KEYCLOAK_PRESET` / `ENTRA_PRESET`
  consts added to `oauth2_passkey/src/oauth2/provider.rs`
- `ProviderKind::{Auth0, Keycloak, Entra}` variants and their `LazyLock`
  statics removed; `ProviderKind::ALL` is now `[Google]`
- `build_custom_provider` consults `OAUTH2_CUSTOM{N}_PRESET` with a 3-level
  fallback (env var > preset default > hardcoded default)
- `OAUTH2_CUSTOM{N}_ICON_SLUG` env var added; shape validated via
  `is_valid_custom_provider_name` at startup
- `resolve_preset` validates preset keys at init; unknown value = fatal error
- Zitadel / Okta / Authentik presets added in commit 5, extending coverage to
  6 presets total
- Per-provider guides (`auth0.md`, `keycloak.md`, `entra.md`) rewritten to
  show `PRESET=...` syntax; `generic-oidc.md` preset table extended to 6 rows
- Local `.env` reorganized: CUSTOM1=Auth0, CUSTOM2=Keycloak, CUSTOM3=Entra,
  CUSTOM4=Zitadel, CUSTOM5=Hydra(bare), CUSTOM6=Authentik, CUSTOM7=Okta
