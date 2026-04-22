# Issue: Configurable `prompt` parameter per OAuth2 provider

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260421-0315

## Created: 2026-04-21-03-15

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

The OIDC `prompt` parameter is hardcoded to `consent` for every provider
in `oauth2_passkey/src/oauth2/provider.rs` (Google, Auth0, Keycloak,
Entra, and every Custom slot). Per OIDC Core 1.0, `prompt=consent` only
tells the IdP to redisplay the consent screen; it does **not** force
re-authentication or account selection. IdPs are therefore free to
reuse an existing authenticated session.

This is observable and mildly confusing during E2E testing against
Zitadel v4 (whose login-v2 service aggressively reuses sessions): after
a first sign-in, every subsequent **Continue with Zitadel** click flows
back without a password or account-picker screen. Same underlying
behavior exists on other IdPs but is less visible because their UIs
insert additional confirmation steps.

Making `prompt` configurable per provider gives operators control
without changing the default (which stays `consent` for backward
compatibility).

See `docs/src/guides/generic-oidc.md` troubleshooting entry "IdP signs
the user in without prompting" and `idp/README.md` entry "Zitadel signs
the user in without prompting" for the user-facing description of the
current behavior.

## Related Issues

- `20260420-1511` Add Generic OIDC Provider Slots (parent; this issue
  surfaced while validating Zitadel v4 end-to-end)

## Approach

Add an optional `OAUTH2_{PROVIDER}_PROMPT` environment variable that
overrides the hardcoded `prompt=consent`:

- For named providers: `OAUTH2_GOOGLE_PROMPT`, `OAUTH2_AUTH0_PROMPT`,
  `OAUTH2_KEYCLOAK_PROMPT`, `OAUTH2_ENTRA_PROMPT`
- For generic slots: `OAUTH2_CUSTOM{N}_PROMPT`
- Default: `"consent"` (no behavior change for existing deployments)

Implementation:

1. Add `prompt: &'static str` to `ProviderConfig` in
   `oauth2_passkey/src/oauth2/provider.rs`
2. For named providers, keep `prompt: "consent"` as a literal
3. For Custom slots, read the env var and `Box::leak` the value (same
   pattern as other custom-slot env fields); default to `"consent"`
4. Replace the five hardcoded `&prompt=consent` occurrences in the
   `auth_url(...)` format strings with `&prompt={prompt}`
5. Treat empty string as "omit the `&prompt=` parameter entirely" — gives
   operators a clean way to let the IdP apply its own default (e.g.
   full SSO / no consent reprompt)
6. Validate the value at startup against the OIDC Core 1.0 set:
   `{"", "none", "login", "consent", "select_account"}`. Space-separated
   combinations (per spec) are intentionally not supported — YAGNI
7. Extend `validate_custom_slots` in `oauth2_passkey/src/oauth2/mod.rs`
   to emit a targeted error for invalid values

Testing:

- Existing URL-assertion tests in `provider/tests.rs` keep passing
  unchanged (default `prompt=consent` preserved)
- Add a test that sets `OAUTH2_CUSTOM1_PROMPT=select_account` and
  asserts the generated URL contains `&prompt=select_account`
- Add a test that sets `OAUTH2_CUSTOM1_PROMPT=""` and asserts `&prompt=`
  is **absent** from the URL
- Add a test that sets an invalid value (e.g. `foobar`) and asserts
  `init()` fails with a validation error

Documentation:

- `dot.env.example`: document the new var under the Custom1 slot block,
  listing the allowed values
- `docs/src/guides/generic-oidc.md`: add the var to the "Optional
  Variables" table and update the "IdP signs the user in without
  prompting" troubleshooting entry to point at it
- `idp/README.md`: update the corresponding Zitadel troubleshooting
  entry likewise

Alternatives considered (rejected):

- **Single global `OAUTH2_PROMPT` env var** — simpler but provides no
  per-IdP control. Different IdPs ship with different SSO UX, so one
  setting won't fit all
- **Demo-side query-param passthrough** (`?prompt=login`) — expands the
  public API surface and removes the operator-side validation guardrail

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` (5 hardcoded `prompt=consent`
  occurrences at lines 383, 426, 467, 510, 592; `ProviderConfig` struct;
  5 LazyLock statics; `optional_env_contract`)
- `oauth2_passkey/src/oauth2/provider/tests.rs` (URL assertion tests at
  lines 503, 541 — plus new cases)
- `oauth2_passkey/src/oauth2/mod.rs` (`validate_custom_slots`)
- `dot.env.example`
- `docs/src/guides/generic-oidc.md` (troubleshooting + optional-vars
  section)
- `idp/README.md` (troubleshooting)

## Implementation Tasks

- [ ] Add `prompt: &'static str` field to `ProviderConfig`
- [ ] Populate named-provider statics with `prompt: "consent"` literals
- [ ] Populate Custom-slot LazyLocks from `OAUTH2_CUSTOM{N}_PROMPT` env
      with `"consent"` default, `Box::leak` for `&'static str`
- [ ] Replace 5 hardcoded `&prompt=consent` occurrences with
      `&prompt={prompt}` (skip the `&prompt=` segment entirely when
      `prompt` is empty)
- [ ] Extend `validate_custom_slots` to reject values outside the OIDC
      Core 1.0 allowed set
- [ ] Unit tests: default preserved, non-default applied, empty value
      omits parameter, invalid value rejected at init
- [ ] `dot.env.example`: document env var + allowed values
- [ ] `docs/src/guides/generic-oidc.md`: add to optional-vars section,
      cross-link from the troubleshooting entry
- [ ] `idp/README.md`: cross-link from the Zitadel troubleshooting entry

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-21: Keep default as `consent`, make per-provider configurable

- Context: Zitadel v4 E2E revealed that `prompt=consent` permits silent
  session reuse, which is confusing during repeated test runs and may
  be undesirable for some deployments (e.g. multi-user kiosks wanting
  `select_account`).
- Decision: Add optional `OAUTH2_{PROVIDER}_PROMPT` env var, default to
  `"consent"` for full backward compatibility, validate at init against
  OIDC Core 1.0 values, and let empty-string omit the parameter.
- Reason: Keeps current behavior for everyone who doesn't set the var;
  gives operators a standard, OIDC-spec-compliant knob. Single global
  var and demo-side passthrough were considered and rejected for
  flexibility / API-surface reasons (see Approach / Alternatives).

## Resolution
