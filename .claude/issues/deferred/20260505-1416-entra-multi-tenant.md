# Issue: Support Entra ID multi-tenant endpoints (common/organizations)

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260505-1416

## Created: 2026-05-05-14-16

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

Microsoft Entra ID supports multi-tenant endpoints (`common`,
`organizations`, `consumers`) for apps that accept users from any Azure
AD tenant or personal Microsoft accounts. Currently only single-tenant
endpoints work because the library's strict issuer validation fails for
multi-tenant discovery documents.

### The problem

When using a multi-tenant endpoint like
`https://login.microsoftonline.com/common/v2.0`:

1. **Discovery fetch fails** (`discovery.rs:86`): The discovery
   document's `issuer` field contains the literal placeholder
   `https://login.microsoftonline.com/{tenantid}/v2.0`, which does not
   match the configured `issuer_url`
   (`https://login.microsoftonline.com/common/v2.0`).

2. **ID token issuer validation would also fail** (`idtoken.rs:409-415`):
   Even if discovery succeeded, the ID token's `iss` claim contains the
   actual tenant UUID (e.g.
   `https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0`),
   which does not match the discovery document's `{tenantid}` placeholder.

### Why single-tenant works

With a tenant-specific endpoint like
`https://login.microsoftonline.com/{actual-tenant-id}/v2.0`, the
discovery `issuer` matches the configured URL exactly, and ID tokens
also carry the same tenant-specific issuer. No placeholder involved.

### Multi-tenant endpoint variants

| Endpoint | Accepts |
|----------|---------|
| `common` | Any Azure AD tenant + personal Microsoft accounts |
| `organizations` | Any Azure AD tenant (work/school only) |
| `consumers` | Personal Microsoft accounts only |
| `{tenant-id}` | Only users from that specific tenant (current support) |

## Related Issues

- `20260420-0552` Add Microsoft Entra ID as OAuth2 Provider (completed — single-tenant)
- `20260226-2020` Expand OAuth2 Provider Support (Phase 5 reference)

## Approach

### Code changes required (2 locations)

#### 1. `discovery.rs:86` — Discovery issuer validation

Current:
```rust
if document.issuer.trim_end_matches('/') != issuer_url {
    return Err(OidcDiscoveryError::IssuerMismatch(...));
}
```

Proposed: If the configured `issuer_url` contains a known multi-tenant
segment (`/common/`, `/organizations/`, `/consumers/`), allow the
discovery document's `issuer` to differ (it will contain `{tenantid}`).
Alternatively, if the discovery `issuer` contains `{tenantid}`, skip the
strict equality check at discovery time and defer validation to the ID
token stage.

```rust
let is_multi_tenant = issuer_url.contains("/common/")
    || issuer_url.contains("/organizations/")
    || issuer_url.contains("/consumers/");
let discovery_issuer = document.issuer.trim_end_matches('/');
if !is_multi_tenant && discovery_issuer != issuer_url {
    return Err(OidcDiscoveryError::IssuerMismatch(...));
}
```

#### 2. `idtoken.rs:409-415` — ID token issuer validation

Current:
```rust
let expected_issuer = ctx.expected_issuer().await?;
if idinfo.iss != expected_issuer {
    return Err(TokenVerificationError::InvalidTokenIssuer(...));
}
```

Proposed: If `expected_issuer` contains `{tenantid}`, replace the
placeholder with the tenant ID extracted from the token's `iss` claim,
then compare. The Entra issuer URL format is predictable:
`https://login.microsoftonline.com/{tenant-id}/v2.0`.

```rust
let expected_issuer = ctx.expected_issuer().await?;
let issuer_valid = if expected_issuer.contains("{tenantid}") {
    // Extract tenant ID from actual issuer and pattern-match
    let pattern_prefix = expected_issuer
        .split("{tenantid}")
        .next()
        .unwrap_or("");
    let pattern_suffix = expected_issuer
        .split("{tenantid}")
        .nth(1)
        .unwrap_or("");
    idinfo.iss.starts_with(pattern_prefix)
        && idinfo.iss.ends_with(pattern_suffix)
} else {
    idinfo.iss == expected_issuer
};
if !issuer_valid {
    return Err(TokenVerificationError::InvalidTokenIssuer(...));
}
```

### Security considerations

- The `{tenantid}` relaxation is only applied when the discovery
  document itself advertises the placeholder — not user-configurable.
- Audience validation (`aud` == `client_id`) remains strict, preventing
  tokens from other apps.
- Signature verification via JWKS is unchanged — tokens must still be
  signed by Microsoft's keys.
- The combination of audience + signature verification provides
  sufficient security even with relaxed issuer validation.

### Configuration

No new env vars needed. The operator simply sets:
```bash
OAUTH2_CUSTOM{N}_ISSUER_URL='https://login.microsoftonline.com/common/v2.0'
```
instead of a tenant-specific URL. The library detects the multi-tenant
case automatically from the discovery document's `{tenantid}` placeholder.

### Verification plan

1. Use existing Azure free account with Entra ID tenant
2. Change app registration "Supported account types" to multi-tenant
3. Set `ISSUER_URL` to `common` endpoint
4. Test login with work account (same tenant)
5. Test login with personal Microsoft account (different tenant)
6. Verify single-tenant still works (regression)

## Related Files

- `oauth2_passkey/src/oauth2/discovery.rs:86` — discovery issuer validation
- `oauth2_passkey/src/oauth2/main/idtoken.rs:409-415` — ID token issuer validation
- `oauth2_passkey/src/oauth2/provider.rs:542-545` — `expected_issuer()` method

## Implementation Tasks

- [ ] Modify `discovery.rs` to skip strict issuer check when `{tenantid}` placeholder detected
- [ ] Modify `idtoken.rs` to pattern-match issuer when `expected_issuer` contains `{tenantid}`
- [ ] Add unit tests: multi-tenant issuer with placeholder matches actual tenant UUID
- [ ] Add unit test: single-tenant issuer validation unchanged (regression)
- [ ] Add unit test: mismatched tenant still fails (security)
- [ ] Change Entra app registration to multi-tenant in Azure portal
- [ ] E2E: login with `common` endpoint + work account
- [ ] E2E: login with `common` endpoint + personal Microsoft account
- [ ] E2E: verify single-tenant endpoint still works
- [ ] Update documentation (`docs/src/guides/generic-oidc.md` Entra section)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-05-05: Issue created

- Context: Entra multi-tenant support was noted as "potential, not
  currently tracked" in the parent issue `20260226-2020`. Investigation
  shows the code change is small (2 locations, ~15 lines each) and
  verification is free (Azure free tier). The only blocker was
  discovery issuer validation + ID token issuer validation.
- Decision: Create dedicated issue. Priority low (no immediate demand)
  but difficulty small (code change is minimal, verification is free).
- Reason: Multi-tenant Entra is a common enterprise requirement for
  SaaS applications. The implementation cost is low enough that it's
  worth tracking as a concrete task rather than a vague future note.

### 2026-05-07: Scope re-evaluation — library work alone is not useful

After deeper discussion, the boundary of what this issue actually
delivers became clearer. Recording it here so future-me does not
re-derive it.

**Library-side changes (this issue's scope, all small)**:
- Relax issuer validation when discovery doc declares `{tenantid}`
  placeholder (~15 lines × 2 files)
- Add `tid: Option<String>` field to `OidcIdInfo`
- Plumb `tid` into `OAuth2Account.metadata` (mirror existing `hd`
  pattern) so the application layer can read it

**Application-side requirements that the library cannot provide**:
- Tenant onboarding flow (manual `tid` entry from Entra admin
  panel — `tid` is publicly retrievable via `Microsoft Entra ID →
  Overview` or `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`,
  and is immutable for the tenant's lifetime, so it is safe to
  store as a natural key)
- Domain-ownership verification (e.g. email-based) to prevent a
  random employee from "claiming" their own org's tenant slot
- First-sign-in `tid` match against the registered tenant record
- tenant ↔ user routing logic for tenant-scoped data

**Why the library alone is not useful**:
- Without app-side onboarding, the library would accept any token
  from any Entra tenant (signature + audience valid), with no way
  for the app to know which tenants are legitimate customers.
  This is *not* a security model — it is "trust whoever shows up".
- The naive "first user wins" pattern (the app records the first
  authenticated user's `tid` as their org's `tid`) is unsafe
  without supplementary domain verification (a random non-admin
  employee could squat on their own employer's tenant slot
  before the real admin signs up). Real SaaS uses Microsoft's
  admin consent gate + email/DNS domain verification + manual
  support escalation as overlapping defenses.
- For pure self-service open-SaaS-style use cases (Slack-shaped),
  the operator already needs onboarding/billing/workspace
  primitives that oauth2-passkey does not provide. Such operators
  are likely to choose a managed identity stack (WorkOS, Clerk,
  Auth0 enterprise) over hand-rolling on top of this library.
- For closed B2B with a known tenant list (a few partners),
  pattern (A) — N Custom slots, one per specific tenant — already
  works today and is operationally simpler.

**Decision**: Keep open at low priority. Do not implement
speculatively. If real demand arrives, the implementer must own
both halves (library + app onboarding), so the issue should not be
labeled "small" in difficulty for the full feature — only the
library-side change is small.

## Resolution
