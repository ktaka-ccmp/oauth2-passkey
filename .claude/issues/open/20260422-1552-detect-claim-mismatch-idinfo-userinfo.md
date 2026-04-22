# Issue: Detect claim mismatch between id_token and /userinfo

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Design](#design)
- [Field Classification](#field-classification)
- [Expected Behavior Matrix](#expected-behavior-matrix)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260422-1552

## Created: 2026-04-22-15-52

## Closed:

## Status: open

## Priority: medium

## Difficulty: small

## Description

The main OAuth2 callback currently only cross-checks `sub` equality
between the verified ID token (`idinfo`) and the `/userinfo` response
(`get_idinfo_userinfo` → `OAuth2Error::IdMismatch`). All other claims
(email, email_verified, name, picture, etc.) are merged silently via
the Option-B `oauth2_account_from_idinfo_and_userinfo` builder: when
both sources populate a field with different values, the ID token
value wins and the `/userinfo` value is silently discarded.

Within a single OAuth2 flow, id_token and /userinfo return the same
user-record snapshot (millisecond time delta, single user session).
Divergence on *any* field is therefore anomalous, not "normal drift".
Identity-critical divergence (email, email_verified, etc.) is a
security concern; display-field divergence is a lower-severity
integrity signal but still worth surfacing.

This issue adds mandatory strict rejection for identity-critical
fields and configurable strict/warn behavior for display fields.

## Related Issues

- `20260421-0105` Merge `idinfo` and `userinfo` — landed the merged
  builder that this issue extends with cross-source validation
- `20260420-1511` Add Generic OIDC Provider Slots — surfaced the
  need for robust multi-IdP validation

## Design

Two-tier classification:

**Tier 1 — Identity/authorization-critical: always reject on mismatch**

These fields drive authn/authz decisions. Divergence is never
acceptable. No env var; the check is hardcoded.

**Tier 2 — Display/metadata: env-var controlled, default reject**

These fields are cosmetic but a mismatch is still anomalous within a
single flow. Operators can opt into warn-only mode per provider.

### Env var

```
OAUTH2_{PROVIDER}_STRICT_DISPLAY_CLAIMS=true   (default) → reject
OAUTH2_{PROVIDER}_STRICT_DISPLAY_CLAIMS=false            → tracing::warn!() and continue
```

Applies to all 4 named providers (`GOOGLE`, `AUTH0`, `KEYCLOAK`,
`ENTRA`) and 8 custom slots (`CUSTOM1`..`CUSTOM8`).

On warn path, the ID token value is used (matches existing Option B
priority). Log format includes `security_event`, `field`, both
values, and provider, so operators can alert on it.

### Error UX

`OAuth2Error::ClaimMismatch { field, idinfo_value, userinfo_value,
provider }`. Error message includes the env var name and how to
relax (only for Tier 2; Tier 1 has no relax path):

```
OAuth2 claim mismatch for provider 'custom1': `name` differs between
id_token ('Alice Smith') and userinfo ('Alice Johnson').
Set OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS=false to downgrade to a
warning.
```

## Field Classification

### Tier 1 — always strict reject (hardcoded)

| Field | Reason for strict |
|---|---|
| `email` | Primary identity; impersonation surface |
| `email_verified` | `true↔false` flip alters auth decision |
| `preferred_username` | Identity fallback (Entra personal, etc.) |
| `hd` | Google Workspace domain — authz decisions |

### Tier 2 — env-var controlled, default reject

| Field | Reason for lower tier |
|---|---|
| `name` | Display label only; no authn/authz impact |
| `picture` | Profile image URL |
| `family_name` | Name component |
| `given_name` | Name component |
| `locale` | User locale preference |

### Out of scope

- `sub` — already strictly checked by `get_idinfo_userinfo`
- `iss`, `aud`, `exp`, `iat`, `nbf`, `nonce`, `jti`, `at_hash`, `azp`
  — not duplicated on `/userinfo`

## Expected Behavior Matrix

Default-configured, tested IdPs. Strict check fires only when both
sides populate the field with different values; "one side None" is
not a mismatch (that is what the Option B merge handles).

| IdP | Tier 1 fire expected? | Tier 2 fire expected? | Notes |
|---|---|---|---|
| Google | ❌ | ❌ | Both endpoints return the same snapshot |
| Auth0 | ❌ | ❌ | Commercial, well-behaved |
| Okta | ❌ | ❌ | Standard OIDC |
| Keycloak (default realm) | ❌ | ❌ | Only fires with custom Token Mapper that intentionally diverges |
| Authentik (default Scope Mapping) | ❌ | ❌ | Only fires with custom Scope Mapping |
| Entra work/school | ❌ | ❌ | `email_verified` often absent in idinfo → one side None, no fire |
| Entra personal (live.com) | ❌ | ❌ | `email` absent in idinfo, carried via `preferred_username` in both — same value |
| Zitadel | ❌ | ❌ | `email` absent in idinfo — one side None, no fire |

**Conclusion:** default=true is empirically safe across all 7 tested
IdPs in default configuration. Fire occurs only when an operator
intentionally configures claim mappers to diverge, which is the
signal this check is designed to surface.

Ory Hydra is excluded from this analysis: it is an OAuth2/OIDC
server that delegates identity to a separate backend (Kratos or
similar), so mismatch behavior is a function of the paired identity
provider, not Hydra itself.

## Related Files

- `oauth2_passkey/src/oauth2/types.rs` — add `validate_claim_match`
  pass in `oauth2_account_from_idinfo_and_userinfo`; add
  `ClaimMismatch` error variant
- `oauth2_passkey/src/oauth2/errors.rs` — `OAuth2Error::ClaimMismatch`
  variant
- `oauth2_passkey/src/oauth2/provider.rs` — new per-provider
  `strict_display_claims: bool` field on `ProviderConfig`, populated
  from `OAUTH2_{PROVIDER}_STRICT_DISPLAY_CLAIMS` at `LazyLock` init
- `oauth2_passkey/src/coordination/oauth2.rs` — pass
  `ctx.strict_display_claims` through to the merged builder
- `oauth2_passkey/src/oauth2/types/tests.rs` — unit tests per field,
  per tier
- `dot.env.example` — document the new env var

## Implementation Tasks

- [ ] Add `OAuth2Error::ClaimMismatch { field, idinfo_value, userinfo_value, provider }`
- [ ] Add `strict_display_claims: bool` to `ProviderConfig`, populate
      from `OAUTH2_{PROVIDER}_STRICT_DISPLAY_CLAIMS` (default `true`)
- [ ] Implement `validate_claim_match` in `types.rs`:
      Tier 1 fields always reject; Tier 2 fields reject or warn based on flag
- [ ] Wire `validate_claim_match` into `oauth2_account_from_idinfo_and_userinfo`
- [ ] Pass `ctx.strict_display_claims` from `coordination/oauth2.rs`
- [ ] Unit tests — per field, match/mismatch/one-sided-None, both tiers
- [ ] Update `dot.env.example` with the new env var block
- [ ] `cargo fmt --all` / `cargo clippy --all-targets --all-features` / `cargo test`
- [ ] E2E retest on Google / Auth0 / Keycloak / Entra / Zitadel /
      Okta / Authentik (all 7 default-config IdPs) — verify no
      spurious reject in happy path

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-22: Tier split and default posture

- Context: `20260421-0105` landed Option B (id_token wins, userinfo
  fallback). Silent field mismatch was noted as a residual concern.
- Decision: Two-tier classification with hardcoded strict reject on
  4 identity-critical fields (email / email_verified /
  preferred_username / hd) and per-provider env-var controlled
  strict/warn on 5 display fields (name / picture / family_name /
  given_name / locale). Default `STRICT_DISPLAY_CLAIMS=true`
  (reject).
- Reason: Identity-critical fields drive authn/authz — never
  acceptable to silently let them diverge, so no env var. Display
  fields are cosmetic — still anomalous within a single flow, but
  breaking login over a `name` mismatch is disproportionate, so an
  escape hatch is reasonable. Default reject matches secure-by-
  default; analysis of 7 tested IdPs shows no spurious fire in
  default configurations.

### 2026-04-22: Rejected designs

- **Warn-only, no reject path**: considered. Rejected because
  silent-if-you-squint "problem hidden" posture is wrong for
  identity-critical divergence.
- **Global `_STRICT` env var**: rejected. Per-provider granularity
  matters — a flaky custom slot should not force policy relaxation
  on Google.
- **3-valued enum env var (`reject` / `warn` / `silent`)**:
  rejected. `silent` is "hide the problem" and has no compelling
  use case that `warn` does not already cover; YAGNI.
- **"Drift is normal" for display fields**: initially argued for a
  silent-display policy on the grounds that user-driven name
  changes could legitimately diverge. Withdrawn: id_token and
  /userinfo are fetched within milliseconds of each other in the
  same flow and reflect the same snapshot. Any divergence is
  anomalous regardless of field.

## Resolution

(pending)
