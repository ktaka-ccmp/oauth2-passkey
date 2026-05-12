# Issue: Correct status labeling for archived design proposals

## Metadata

- ID: 20260512-0351
- Created: 2026-05-12-03-51
- Closed: 2026-05-12-05-13
- Status: completed
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2018` Simplify OAuth2 Account Linking API (parent — surfaced as a side finding in its Timeline entry on 2026-05-12T02:46)
  - `20260512-0335` POST-based OAuth2 account linking initiation (Alt 5B validation) (the proposal being mislabeled is what this issue family is reconsidering)

## Problem

`docs/src/archived/README.md:28-37` lists design proposals under
the heading "**Implemented** design documents and proposals":

> ## Design Proposals
>
> Implemented design documents and proposals:
>
> - cache-expiration-system-simplification.md
> - implementing-tracing.md
> - integration-testing-plan.md
> - oauth2-account-linking-api-simplification.md   ← not implemented
> - testing-oidc-discovery.md
> - TestKeyPairGeneration.md
> - type-safe-validation.md

The `oauth2-account-linking-api-simplification.md` entry is
incorrect — none of its proposed APIs
(`auth_user.create_oauth2_link_url(...)`, provider-specific trait
methods, builder pattern, middleware) have been implemented. Its
concrete recommendations have also been critiqued (see
`20260226-2018` Timeline 2026-05-12T02:46) and the underlying
architectural alternative is now under validation as
`20260512-0335`.

Listing the proposal under "Implemented" misleads readers about
what code exists in the library, and risks future contributors
treating the design proposal's recommendations as authoritative.

## Timeline

### 2026-05-12T03:51 — Issue created from parent's side findings

Surfaced during the analysis recorded in `20260226-2018` Timeline
entry 2026-05-12T02:46.

## Latest Plan

Two changes:

### 1. Restructure `docs/src/archived/README.md`

Split the Design Proposals list into clearly-labeled subsections:

```markdown
## Design Proposals

### Implemented

- cache-expiration-system-simplification.md
- implementing-tracing.md
- integration-testing-plan.md
- testing-oidc-discovery.md
- TestKeyPairGeneration.md
- type-safe-validation.md

### Superseded / Not Implemented

- oauth2-account-linking-api-simplification.md — see issues
  `20260226-2018` and `20260512-0335` for current status
```

While restructuring, spot-check the remaining "Implemented" entries
to confirm they really were implemented (cheap to verify; avoids
leaving the list in a partially-known state).

### 2. Annotate the proposal itself

Prepend a status notice at the top of
`docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`:

```markdown
> **Status: Superseded.** The specific API recommendations in this
> document (one-function `.await`, provider-specific traits, builder
> pattern, middleware) were critiqued and rejected in issue
> `20260226-2018` Timeline entry 2026-05-12T02:46. The architectural
> question this proposal tried to address is being reconsidered
> under issue `20260512-0335` (POST-based linking initiation, which
> would eliminate the `page_session_token` concept entirely).
```

### Files

- `docs/src/archived/README.md`
- `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`

### Implementation Tasks

- [x] Restructure `archived/README.md` Design Proposals into "Implemented" and "Superseded / Not Implemented"
- [x] Spot-check that each remaining "Implemented" entry has corresponding implementation in code; reclassify any that don't
- [x] Prepend Status notice to `oauth2-account-linking-api-simplification.md`
- [x] If the mdBook build is part of CI, verify it still passes

### Verification

- `docs/src/archived/README.md` renders correctly (`mdbook build docs` if set up)
- Each listed proposal's status accurately reflects code reality

## Resolution

Branch: `chore/archived-proposals-labeling`.

Spot-check confirmed all 6 remaining proposals listed under
"Implemented" are in fact implemented (evidence per Latest Plan):

- `cache-expiration-system-simplification` — TTL/expiration logic in
  `oauth2_passkey/src/storage/types.rs` and
  `cache_store/{memory,redis}.rs`
- `implementing-tracing` — `tracing::` used across core
  (`utils.rs`, `session/config.rs`, `oauth2/main/oidc.rs`, etc.)
- `integration-testing-plan` — `oauth2_passkey_axum/tests/integration/`
  (`api_client_flows.rs`, `combined_flows.rs`, `oauth2_flows.rs`,
  `passkey_flows.rs`)
- `testing-oidc-discovery` — `oauth2_passkey/src/oauth2/discovery/tests.rs`
- `TestKeyPairGeneration` — `oauth2_passkey/src/coordination/passkey/tests.rs`
- `type-safe-validation` — newtypes (`UserId`, `ProviderName`, etc.)
  exposed in `oauth2_passkey/src/lib.rs`

Changes landed:

1. `docs/src/archived/README.md` — Design Proposals section split
   into "Implemented" (6 entries) and "Superseded / Not Implemented"
   (1 entry, `oauth2-account-linking-api-simplification.md` with
   inline pointer to issues `20260226-2018` and `20260512-0335`).
2. `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`
   — Status notice blockquote prepended right after the H1, citing
   the parent issue Timeline entry and the architectural
   reconsideration tracked under the child issue.

`mdbook build docs` clean.
