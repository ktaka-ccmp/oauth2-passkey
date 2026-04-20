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

## Closed:

## Status: open

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
- [ ] Add `CustomSlot` enum + `Custom(CustomSlot)` variant to `ProviderKind`
- [ ] Add 4 `LazyLock<Option<ProviderConfig>>` statics (CUSTOM1..CUSTOM4)
- [ ] Extend `ProviderConfig` with `display_name` / `button_class` / `button_color` / `button_hover_color`
- [ ] Extend `optional_env_contract` to validate custom slot env shape
- [ ] Path segment collision detection at LazyLock init
- [ ] `from_path_segment` resolves custom slot path segments dynamically
- [ ] `provider_for` arm for `Custom(slot)`

### UI
- [ ] `provider_view` reads `display_name` / `button_class` from config
- [ ] Inline CSS generation for custom slot button colors in login template
- [ ] Verify UI button renders correctly for a custom slot

### Tests
- [ ] Test: custom slot env validation (trigger + deps)
- [ ] Test: path segment collision detection
- [ ] Test: invalid path segment characters rejected
- [ ] Test: slot falls back to defaults when optional env absent
- [ ] Regression: all named providers still work

### Docs
- [ ] Update `dot.env.example` with `OAUTH2_CUSTOM1_*` block
- [ ] Write `docs/src/guides/generic-oidc.md`:
  - List of tested OIDC providers (Okta, AWS Cognito, Zitadel, Ory Hydra, Dex, Authelia, Salesforce, GitLab)
  - Per-provider setup hints (issuer URL, scope quirks)
  - Troubleshooting (most issuer-mismatch / JWKS issues already surfaced)
- [ ] Add entry to `docs/src/SUMMARY.md`

### Verification (pick 2-3 providers to end-to-end test)
- [ ] Okta Developer Account login succeeds (free dev tenant)
- [ ] Zitadel or Ory Hydra self-host login succeeds (Docker)
- [ ] AWS Cognito login succeeds (free tier)
- [ ] Verify named providers (Google/Auth0/Keycloak/Entra) untouched

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

## Resolution
