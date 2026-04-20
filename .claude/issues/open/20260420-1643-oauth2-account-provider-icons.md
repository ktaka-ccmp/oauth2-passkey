# Issue: Show IDP Icon and Provider Name on OAuth2 Account Cards

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-1643

## Created: 2026-04-20-16-43

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

The `/o2p/user/account` page currently shows each linked OAuth2 account as a plain card
with provider name hidden inside a commented-out `<div>`. Unlike passkey credential cards
— which display an authenticator icon (`.authenticator-icon`, 36px) next to the
authenticator name — OAuth2 account cards have no visual indicator of which IDP the
account belongs to. A user with accounts from multiple providers (Google, Auth0,
Keycloak, Entra) has to read the email domain to distinguish them.

This issue adds:

1. A small IDP logo (24px) in the **top-right corner** of each OAuth2 account card,
   absolutely positioned.
2. The IDP name exposed in the card body (uncomment existing `{{ account.provider }}`
   line) and as the icon's `alt` / `title` for accessibility.
3. Profile picture handling left unchanged (Google / Auth0 show it; Keycloak / Entra
   typically don't).

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (parent: this improves UX of the
  features added by that effort)
- `20260420-1456` Add LINE Login as OAuth2 Provider (when added, needs a matching icon)
- `20260420-1457` Add Sign in with Apple as OAuth2 Provider (same)
- `20260420-1458` Add GitHub as OAuth2 Provider (same)
- `20260420-1511` Add Generic OIDC Provider Slots (needs a neutral fallback icon)

## Approach

### Icon source: Simple Icons (CC0)

Use [Simple Icons](https://simpleicons.org/) SVGs. The icon data itself is CC0; the
trademarks remain with the respective companies. Using them to indicate "account linked
via X" is standard nominative fair use. Ship the SVGs in-tree (`oauth2_passkey_axum/static/icons/`)
rather than hotlinking.

Icons needed for the currently-implemented providers:

| Provider | Simple Icons slug | Brand color |
|---|---|---|
| Google | `googleg` (the standalone "G" mark) | `#4285F4` (already in CSS as `--o2p-google`) |
| Auth0 | `auth0` | `#EB5424` (already `--o2p-auth0`) |
| Keycloak | `keycloak` | `#4D4D4D` (already `--o2p-keycloak`) |
| Microsoft (Entra) | `microsoft` (4-color tile) | `#0078D4` (already `--o2p-entra`) |

Each SVG is ~1-2 KB. Add an attribution line to `oauth2_passkey_axum/CREDITS.md` (new
file) or to the crate README noting "Provider icons from Simple Icons (CC0)".

### Rendering: `<img>` tag, not `mask-image`

**Rejected alternative**: CSS `mask-image` (where a single monochrome SVG is tinted via
`background-color: var(--o2p-google)`). Does not work for multi-color brand marks
(Google's 4-color G, Microsoft's 4-color tile) which would be flattened to a single
color. The existing `.authenticator-icon` in the codebase also uses `<img>`, so this
keeps the style consistent.

### Layout: absolute position, top-right

The card uses `.item.oauth2 { padding: var(--o2p-space-sm); }` (approx) with a left
border accent. Add `position: relative` to the card and position the icon absolutely:

```css
.item.oauth2 {
    position: relative;
}
.provider-icon {
    position: absolute;
    top: var(--o2p-space-sm);
    right: var(--o2p-space-sm);
    width: 24px;
    height: 24px;
    object-fit: contain;
}
```

This keeps the icon out of the existing content flow (no disruption to the profile
picture / detail rows) and mirrors where a "favicon" would sit on a browser tab.

### Provider name in body

Line 150 of `user_account.j2` is currently commented out:

```html
<!-- <div class="item-detail"><strong>Provider:</strong> {{ account.provider }}</div> -->
```

Uncomment it, capitalize the display value (`entra` → `Entra`, `auth0` → `Auth0`). The
simplest approach is a Jinja filter in the template using the existing `ProviderKind`
display name — but since the template takes `account.provider` as a raw string, a small
filter function or a server-side lookup is needed. See Implementation Tasks below for
the trade-off.

### Generic OIDC fallback

For `20260420-1511` (generic OIDC slots), use a neutral key icon (Simple Icons
`openid`, `#F78C40`) or a generic "link" icon. Not in scope for this issue but noted
so the CSS naming doesn't paint us into a corner.

## Related Files

- `oauth2_passkey_axum/templates/user_account.j2` — add `<img class="provider-icon">`
  in each OAuth2 account `.item.oauth2` block, uncomment the Provider detail row
- `oauth2_passkey_axum/static/o2p-base.css` — add `.provider-icon` positioning rules;
  add `position: relative` to `.item.oauth2`
- `oauth2_passkey_axum/static/icons/` *(new directory)* — `google.svg`, `auth0.svg`,
  `keycloak.svg`, `entra.svg` from Simple Icons
- `oauth2_passkey_axum/src/router.rs` *(or equivalent static serving point)* — verify
  that the new icon path is served under the static prefix (e.g. `/o2p/static/icons/…`)
- `oauth2_passkey_axum/CREDITS.md` *(new, or append to README)* — Simple Icons
  attribution

### Display-name resolution

Add a display-name helper that maps `account.provider` (lowercase slug) to a human
label. Either:

- **Option A**: Expose a method on the template context — populate a pre-computed
  `display_name` alongside `provider` when building the template model. Cleanest.
- **Option B**: Template-side if/elif chain. Quickest to ship, ugliest to maintain.
- **Option C**: `ProviderKind::display_name(&self) -> &'static str` in
  `oauth2_passkey/src/oauth2/provider.rs`, exposed via a lookup in the handler that
  builds `user_account.j2` data. Most consistent with the existing `ProviderKind`
  abstraction.

**Recommendation: Option C.** `ProviderKind` already has `as_str()` (slug) and
`optional_env_contract()`. Adding `display_name()` parallels that and keeps the
provider-specific string table in one place. The handler that renders the account
page already has access to each account's provider string — it can call
`ProviderKind::from_path_segment(&account.provider).map(|k| k.display_name())` and
fall back to the raw slug for unknown providers (generic OIDC slots, future providers).

## Implementation Tasks

### Display-name resolution (order-dependent with `20260420-1511`)

Pick **one** path based on whether `20260420-1511` (generic OIDC slots) has landed:

- **If 1511 has NOT landed yet**: add `ProviderKind::display_name(&self) -> &'static
  str` returning `"Google"`, `"Auth0"`, `"Keycloak"`, `"Microsoft"` (note: Entra's
  UI label is "Microsoft" to match the login button). Unit test all variants in
  `oauth2_passkey/src/oauth2/provider/tests.rs`.
- **If 1511 HAS landed**: skip the enum method — `ProviderConfig` already exposes
  `display_name` as a field. Use `provider_for(kind).map(|c| c.display_name)` with
  a slug fallback for unknown providers (generic OIDC custom slots store their own
  `display_name` per-slot). In this case the only lookup work is in the handler.

### Everything else

- [ ] Extend the handler that builds `UserAccountTemplate` context (find in
      `oauth2_passkey_axum/src/`) to compute a `provider_display_name` per OAuth2
      account, falling back to the raw slug when the provider isn't recognised
- [ ] Download four branded Simple Icons SVGs into
      `oauth2_passkey_axum/static/icons/` (google.svg, auth0.svg, keycloak.svg,
      entra.svg — using the `microsoft` source for Entra since the Microsoft
      multi-color tile is the user-facing brand)
- [ ] Download one neutral fallback SVG: `openid.svg` from Simple Icons. This is
      the icon that `20260420-1511` custom slots (and any future unrecognised
      provider with `OAUTH2_*` credentials) will render with. Shipping it as part
      of this issue means 1511 does not need any icon work of its own
- [ ] Update `user_account.j2`:
      - Add `<img class="provider-icon" src="{static_prefix}/icons/{{ icon_slug }}.svg"
        alt="{{ provider_display_name }}" title="{{ provider_display_name }}">` at
        the top of each `.item.oauth2` block
      - `icon_slug` is `account.provider` if a branded SVG exists for it, otherwise
        `"openid"` — resolution happens in the handler when building the template
        context, not in the template
      - Uncomment the Provider detail row; use `{{ provider_display_name }}`
- [ ] Update `o2p-base.css`:
      - `.item.oauth2 { position: relative; }`
      - `.provider-icon { position: absolute; top: …; right: …; width: 24px; height: 24px; object-fit: contain; }`
      - Responsive check: on narrow viewports (`@media (max-width: …)`), confirm
        the icon doesn't overlap the profile picture
- [ ] Add Simple Icons attribution (CC0 but courtesy attribution) to
      `oauth2_passkey_axum/README.md` or a new `CREDITS.md`
- [ ] Manual verification on `demo-both` with all four providers linked:
      - Google icon visible, correct color, not clipped
      - Auth0 icon visible
      - Keycloak icon visible (local keycloak idp)
      - Entra icon visible (personal MS account via passkey-demo.ccmp.jp)
      - Layout doesn't break when account has no profile picture (Keycloak/Entra)
      - Layout doesn't break when account has long email/name
      - Dark-mode (if applicable) doesn't tint the icon oddly — Simple Icons
        full-color SVGs should render identically
- [ ] `cargo fmt --all && cargo clippy --all-targets --all-features && cargo test`
- [ ] Screenshot before/after in the PR description

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Use Simple Icons (CC0) over official brand kits

- Context: Choosing between Simple Icons SVGs and official brand assets from each
  provider (Google Sign-In Branding, Microsoft brand assets, etc.)
- Decision: Use Simple Icons
- Reason: Official brand kits come with extensive size/color/spacing constraints that
  lock the UI into provider-dictated layouts and are designed primarily for the
  pre-auth "Sign in with X" button, not for a post-auth "linked account" indicator.
  Simple Icons is a CC0-licensed, uniformly-sized catalog used across many open-source
  projects for exactly this kind of nominative use. Trademark rights remain with each
  vendor; this usage is standard nominative fair use (identifying a service, no
  endorsement implied).

### 2026-04-20: `<img>` tag over CSS `mask-image`

- Context: Two rendering techniques — plain `<img src=".svg">` or `background-color +
  mask-image` to allow CSS-controlled tinting
- Decision: Plain `<img>`
- Reason: Google's 4-color "G", Microsoft's 4-color tile, and Auth0's shaded mark are
  multi-color brand signatures. `mask-image` flattens to a single `background-color`
  which would misrepresent the brand. Also, the existing `.authenticator-icon`
  pattern (passkey cards) uses `<img>` — matching it keeps the codebase consistent.

### 2026-04-20: Display-name lookup via `ProviderKind::display_name()`

- Context: Need a user-facing label different from the internal slug (`entra` →
  "Microsoft"). Options: template if/elif chain, helper on the template context, or
  method on `ProviderKind`.
- Decision: Add `ProviderKind::display_name(&self) -> &'static str` and resolve in the
  handler
- Reason: The `ProviderKind` enum is already the canonical home for per-provider
  string constants (slug via `as_str()`, env-var contract via
  `optional_env_contract()`). Adding `display_name()` keeps the table in one place.
  Template-side if/elif would duplicate the variant list across Rust and Jinja, and
  handler-side lookup tables would fragment the same mapping.

### 2026-04-20: Coordination with `20260420-1511` (Generic OIDC Slots)

- Context: Issue `20260420-1511` plans to add `display_name` / `button_class` / etc.
  as **fields on `ProviderConfig`** so generic OIDC custom slots can supply their
  label from env vars. The original plan here (put `display_name` on `ProviderKind`)
  would conflict: an enum method can't return a user-configured string for runtime-
  decided custom slots.
- Decision:
  1. If 1643 lands first, add `ProviderKind::display_name()` — when 1511 lands it
     migrates the source of truth to `ProviderConfig.display_name` and removes the
     enum method. Small handover cost; acceptable.
  2. If 1511 lands first, skip the enum method entirely and read
     `ProviderConfig.display_name`. Cleaner.
  3. Ship `openid.svg` as a neutral fallback icon here so 1511's custom slots can
     reuse it without needing any icon work of their own.
- Reason: 1511 is marked `high` priority and 1643 is `low`, so 1511 will likely land
  first in practice — but the branded icons + positioning CSS in this issue are
  genuinely independent of the generic-slots design and shouldn't be blocked on it.
  The conditional task above documents both orderings explicitly. Shipping the
  fallback icon here avoids asset work fragmentation between the two issues.

## Resolution

<!-- filled in when closed -->

