# Issue: Add Generic OIDC Provider Slots

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1511

## Created: 2026-04-20-15-11

## Closed: 2026-04-21

## Status: completed

## Priority: high

## Difficulty: medium

## Description

Introduce generic "Custom OIDC" provider slots so users can enable any
standards-compliant OIDC provider via environment configuration alone, without
needing a code change or library fork. This expands supported providers from
a fixed list to "any OIDC-compliant IdP" with a single implementation effort.

### Motivation

Since Keycloak (`20260420-0307`) and Entra (`20260420-0552`) landed, the
OIDC code path has been validated against three distinct providers
(Google, Auth0, Keycloak, Entra). Empirically, any standards-compliant OIDC
provider works with the existing flow given only:

- `client_id`
- `client_secret`
- `issuer_url` (used for discovery)

Providers that would be unlocked by generic OIDC slots without any new
per-provider code:

- **Okta** (enterprise SSO; free Developer Account for testing)
- **AWS Cognito** (50,000 MAU free tier)
- **Zitadel** (OSS IAM; cloud free tier or self-host)
- **Ory Hydra** (OSS OIDC provider, self-host)
- **Dex** (OSS OIDC provider that federates other IdPs)
- **Authelia** (OSS SSO/2FA, self-host)
- **Salesforce** (Developer Edition free)
- **GitLab** (gitlab.com free or self-host)
- **Microsoft Entra External ID** (was Azure AD B2C)
- (and any future OIDC provider)

### Design constraint

Preserve the 2026-04-16 decision: **no HashMap-based `ProviderRegistry`**.
The provider set must remain code-defined with `match` exhaustiveness
enforcement. This means the generic slots are implemented as a fixed-count
set of enum variants (e.g. `Custom1`..`Custom4`), not a dynamic registry.

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (relationship: part of)
- `20260420-0552` Add Entra Provider (relationship: validates the OIDC code
  path that generic slots reuse)
- `20260420-1643` Show IDP Icon and Provider Name on OAuth2 Account Cards
  (relationship: account-page icon work — landed 2026-04-20 ahead of this
  issue. Ships `openid.svg` fallback that custom slots here reuse; no new
  icon assets needed in this issue. Consolidation pending here:
  - 1643 landed with free functions `display_name_for(&str) -> &str` and
    `icon_slug_for(&str) -> &'static str` in
    `oauth2_passkey_axum/src/oauth2.rs` (not a method on `ProviderKind`).
    When this issue adds `ProviderConfig.display_name` /
    `ProviderConfig.button_class`, migrate the source of truth to
    `ProviderConfig` and delete both helpers. `provider_view` in the
    axum crate already duplicates the same provider table and should be
    folded into the same migration.
  - `icon_slug_for` currently returns `"openid"` for any unknown slug,
    which is the right behavior for generic OIDC slots: custom slots
    render with the neutral OpenID mark. No per-slot icon env var is
    needed (YAGNI — revisit if deployers ask).)

## Approach

### Enum extension

```rust
pub(crate) enum ProviderKind {
    Google,
    Auth0,
    Keycloak,
    Entra,
    Custom(CustomSlot),
}

pub(crate) enum CustomSlot { Slot1, Slot2, Slot3, Slot4 }
```

- Named variants retain their specialised behavior (Google's FedCM hook, etc.)
- `Custom(_)` variants use the shared OIDC code path with env-driven config

### Slot env-var shape

Per slot (using `CUSTOM1` as example):

```bash
OAUTH2_CUSTOM1_CLIENT_ID='...'              # trigger
OAUTH2_CUSTOM1_CLIENT_SECRET='...'
OAUTH2_CUSTOM1_ISSUER_URL='https://...'
OAUTH2_CUSTOM1_DISPLAY_NAME='My SSO'        # UI button label
OAUTH2_CUSTOM1_PATH_SEGMENT='my-sso'        # URL path (must be unique, [a-z0-9_-]+)
OAUTH2_CUSTOM1_BUTTON_COLOR='#4A90E2'       # optional, default neutral gray
OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR='#357ABD' # optional, derived from button_color if absent
OAUTH2_CUSTOM1_RESPONSE_MODE='form_post'    # optional, default form_post
OAUTH2_CUSTOM1_SCOPE='openid+email+profile' # optional, default
```

Validation at startup (`optional_env_contract`-style):
- If `_CLIENT_ID` is set, all of `_CLIENT_SECRET`, `_ISSUER_URL`,
  `_DISPLAY_NAME`, `_PATH_SEGMENT` must be set
- `_PATH_SEGMENT` must match `[a-z0-9_-]+` and not collide with named
  providers (`google`, `auth0`, `keycloak`, `entra`, `authorized`, `accounts`,
  `fedcm`, `popup_close`, `oauth2.js`) or other enabled slots

### Path segment mapping

`ProviderKind::from_path_segment` now returns `Some(ProviderKind::Custom(slot))`
if the segment matches one of the configured custom slot path segments.
Collision detection happens at `LazyLock` init; duplicates cause startup panic.

### `provider_view` handling

`display_name` and `button_class` must come from the `ProviderConfig` instead
of being hardcoded in the axum crate:

```rust
pub(crate) struct ProviderConfig {
    // ... existing fields
    pub(crate) display_name: &'static str,   // or String for custom slots
    pub(crate) button_class: &'static str,   // or String for custom slots
}
```

For named providers, `display_name` / `button_class` are compile-time constants.
For custom slots, they come from env vars.

### CSS generation

Two approaches:

**Approach A (recommended)**: emit an inline `<style>` tag in the login
template with the custom-slot button colors. No CSS file modification needed;
colors flow from env to runtime CSS.

**Approach B**: generate `.btn-custom1` ... `.btn-custom4` classes in
`o2p-base.css` with CSS variables, and update variables at runtime via
`style="--o2p-custom1: #...;"` on the button element.

Approach A is simpler and keeps the CSS file static.

### Scope: not included in this issue

- **Non-OIDC providers** (GitHub) — handled separately in `20260420-1458`
- **Dynamic secret** (Apple) — handled separately in `20260420-1457`
- **Slot count** — fixed at 4 for now; revisit if demand for more appears
- **FedCM** — generic slots do not participate in FedCM (Google-only)

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` — add `CustomSlot` enum + 4 LazyLock statics
- `oauth2_passkey/src/oauth2/provider/tests.rs` — tests for slot env validation + collision
- `oauth2_passkey_axum/src/oauth2.rs` — `provider_view` reads display_name from config
- `oauth2_passkey_axum/src/templates/` — login template emits inline CSS for custom slots
- `dot.env.example` — document `OAUTH2_CUSTOM1_*` env vars
- `docs/src/guides/generic-oidc.md` — new setup guide with tested IdP list

## Implementation Tasks

### Core implementation
- [x] Add `CustomSlot` enum + `Custom(CustomSlot)` variant to `ProviderKind`
- [x] Add 4 `LazyLock<Option<ProviderConfig>>` statics (CUSTOM1..CUSTOM4) — **scope expanded to 8 slots (CUSTOM1..CUSTOM8)** during implementation to enable parallel E2E testing of multiple IdPs
- [x] Extend `ProviderConfig` with `display_name` / `button_class` / `button_color` / `button_hover_color` (plus `icon_slug`, `path_segment`, `css_var_suffix` folded in from issue 20260420-1643)
- [x] Extend `optional_env_contract` to validate custom slot env shape
- [x] Path segment collision detection at LazyLock init (`validate_custom_slots` + `RESERVED_PATH_SEGMENTS`)
- [x] `from_path_segment` resolves custom slot path segments dynamically
- [x] `provider_for` arm for `Custom(slot)`

### UI
- [x] `provider_view` reads `display_name` / `button_class` from config (`display_name_for` / `icon_slug_for` helpers deleted)
- [x] Inline CSS generation for custom slot button colors in login template (`custom_css_vars_block` + `.btn-custom1..8` rules in `o2p-base.css`)
- [x] Verify UI button renders correctly for a custom slot (E2E-verified against all 4 tested IdPs)

### Tests
- [x] Test: custom slot env validation (trigger + deps)
- [x] Test: path segment collision detection (reserved + named-provider + cross-slot duplicate)
- [x] Test: invalid path segment characters rejected
- [x] Test: slot falls back to defaults when optional env absent (`custom_slot_custom_button_colors_applied`, etc.)
- [x] Regression: all named providers still work

### Docs
- [x] Update `dot.env.example` with `OAUTH2_CUSTOM1_*` block
- [x] Write `docs/src/guides/generic-oidc.md`:
  - List of tested OIDC providers (Zitadel, Ory Hydra, Authentik, Okta — full step-by-step sections)
  - Per-provider setup hints (issuer URL, scope quirks)
  - Troubleshooting (issuer-mismatch / JWKS / `CONFORMITY_FAKE_CLAIMS` for Hydra)
- [x] Add entry to `docs/src/SUMMARY.md`

### Verification (pick 2-3 providers to end-to-end test)
- [x] Okta Developer Account login succeeds (free dev tenant)
- [x] Zitadel or Ory Hydra self-host login succeeds (Docker) — **both verified** plus Authentik (4 OSS/commercial IdPs total)
- [ ] AWS Cognito login succeeds (free tier) — **intentionally skipped**. Verification scope already exceeded the "pick 2-3" guidance with Zitadel / Hydra / Authentik / Okta. AWS Cognito remains uncovered; if a user hits an issue, add coverage in a follow-up.
- [x] Verify named providers (Google/Auth0/Keycloak/Entra) untouched

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Fixed-slot design over HashMap registry

- Context: Adding arbitrary OIDC providers could be done via a dynamic
  `HashMap<String, ProviderConfig>` registry keyed on slot name. This was
  deliberately rejected in 2026-04-16 for the named-provider design.
- Decision: Use a fixed `CustomSlot` enum with 4 variants. Users can
  enable 0-4 custom OIDC providers at a time.
- Reason: Preserves `match` exhaustiveness at compile time. Avoids runtime
  init lifecycle for a registry. 4 slots is empirically enough for most
  deployments (named providers take the most common cases already).
  Revisit if multiple users report hitting the cap.

### 2026-04-20: Non-OIDC and dynamic-secret providers kept separate

- Context: Generic OIDC slots could be extended to cover GitHub (non-OIDC)
  and Apple (dynamic JWT secret) by adding per-slot flow-type and
  secret-strategy fields.
- Decision: Keep this issue scoped to OIDC-only with static secrets.
  GitHub and Apple remain separate issues.
- Reason: The value of generic slots is that they are a trivial extension
  of the existing OIDC path. Mixing in non-OIDC and dynamic-secret variants
  would reintroduce all the architectural complexity those issues are
  designed to handle carefully. Independent issues keep scope clean.

### 2026-04-20: 1643 presentation migration folded into this issue

- Context: Issue `20260420-1643` left `display_name_for(&str)` and
  `icon_slug_for(&str)` free functions in `oauth2_passkey_axum/src/oauth2.rs`
  with a note to migrate the source of truth to `ProviderConfig` when
  `display_name` / `button_class` fields landed.
- Decision: Do the migration here. `ProviderConfig` gains
  `path_segment`, `display_name`, `button_class`, `icon_slug`,
  `button_color`, `button_hover_color`. Public `ProviderInfo` carries
  the presentation fields. Axum's `provider_view` becomes a thin
  `ProviderInfo`-to-`ProviderView` mapping; both free helpers deleted.
- Reason: Custom slots must source presentation data from config anyway
  (env-driven). Keeping named providers on the hardcoded match while
  custom slots go through config would leave two parallel systems. One
  source of truth is simpler.

### 2026-04-20: CSS approach — hybrid CSS vars + inline `<style>` block

- Context: Three options considered — (A) all CSS rules inline in the
  template, (B) per-button `style="--o2p-customN: #..."` attributes, or
  hybrid (`.btn-customN` classes in `o2p-base.css` using CSS vars, plus
  inline `<style>` in the template setting `:root { --o2p-customN: #...; }`
  for enabled slots).
- Decision: Hybrid.
- Reason: `o2p-base.css` already defines `.btn-google`, `.btn-auth0`
  etc. using `var(--o2p-<provider>)`, and `theme-*.css` files override
  via `:root`. Hybrid extends the existing pattern instead of introducing
  a third styling mechanism. Four extra classes in the base CSS is a
  trivial cost.

### 2026-04-20: E2E verification scope — Zitadel + Ory Hydra (OSS only)

- Context: The issue's task list lists Okta, Zitadel/Ory Hydra, and AWS
  Cognito as candidates for real-IdP E2E verification.
- Decision: Verify against Zitadel and Ory Hydra (both self-hostable via
  Docker). Skip Okta and Cognito for this issue.
- Reason: Two structurally different OSS OIDC stacks validate the generic
  code path without depending on external accounts. Cloud IdP coverage
  can be added in a follow-up if operators report breakage.

### 2026-04-20: Implementation plan finalized

Plan file: `/home/ktaka/.claude/plans/optimized-tinkering-pudding.md`
(personal, not checked in). Contains concrete code sketches for
`CustomSlot`, extended `ProviderConfig`, `validate_custom_slots`, the
hybrid CSS approach, and the 11-step build sequence.

## Resolution

Landed on branch `feature/generic-oidc-provider-slots` (to be merged via PR).

### What was implemented

- `ProviderKind::Custom(CustomSlot)` with 8 slots (`Slot1..Slot8`) —
  expanded from the originally planned 4 after real-world use indicated
  operators might want to run more than 4 simultaneous custom IdPs (e.g.
  parallel testing of Zitadel, Hydra, Authentik, Okta without re-shuffling
  slot numbers).
- `ProviderConfig` extended with `path_segment`, `display_name`,
  `button_class`, `icon_slug`, `button_color`, `button_hover_color` —
  single source of truth for all presentation data (folds in the
  `20260420-1643` migration).
- `CUSTOM{1..8}_PROVIDER` `LazyLock<Option<ProviderConfig>>` statics, each
  reading `OAUTH2_CUSTOM{N}_*` env vars with sensible defaults
  (`response_mode=form_post`, `scope=openid+email+profile`, neutral gray
  buttons).
- `validate_custom_slots()` pass in `oauth2::init()` enforcing path_segment
  shape (`[a-z0-9_-]+`), no collision with named providers or reserved
  routes, no duplicates among enabled slots.
- Axum layer: `provider_view` and `enabled_providers` consume the new
  `ProviderConfig` fields directly; `display_name_for` and `icon_slug_for`
  free helpers removed.
- Templates: `custom_css_vars_block()` emits inline `:root { --o2p-customN: ... }`
  in `<head>` for enabled slots only; `.btn-custom1..8` classes in
  `o2p-base.css` pick up the variables.
- Docs: new `docs/src/guides/generic-oidc.md` with step-by-step setup for
  Zitadel, Ory Hydra, Authentik, and Okta (all E2E-verified);
  `dot.env.example` documents the CUSTOM1 block and notes slots 2-8
  share the same shape.
- IdP bring-up scripts under `idp/` (Zitadel v1/v4, Ory Hydra, Authentik)
  with `idp/README.md` covering Docker Compose setup and per-provider
  gotchas discovered during verification.

### E2E verification performed

Beyond the originally planned Zitadel + Ory Hydra scope:

- **Zitadel** (self-host, Docker) — works.
- **Ory Hydra** (self-host, Docker) — works. Required documenting two
  upstream quirks: `token_endpoint_auth_method=client_secret_post`
  (library uses form-body credentials) and the reference consent app's
  `CONFORMITY_FAKE_CLAIMS=1` for emitting email/preferred_username/picture.
- **Authentik** (self-host, Docker) — works.
- **Okta** (cloud, developer edition) — works. Required documenting the
  two-layer policy model: App Authentication Policy must allow login, and
  the Custom Authorization Server needs its own Access Policy. System Log
  (`no_matching_policy`) is authoritative for diagnosing either.
- Named-provider regression (Google / Auth0 / Keycloak / Entra) — all
  still work unchanged.

### Deviations from the plan

- Slot count: 4 → 8 (noted above).
- Okta added to the E2E list mid-flight once a real operator request
  surfaced; docs updated with the full policy-layer gotcha.
- Hybrid CSS approach implemented as planned.
- `1643` presentation migration folded in as planned.
