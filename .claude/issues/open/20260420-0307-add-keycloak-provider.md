# Issue: Add Keycloak as OIDC Provider

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-0307

## Created: 2026-04-20

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

Add Keycloak as a second OIDC provider alongside Google and Auth0. Keycloak is
a widely-used open-source identity provider (self-hosted or cloud-hosted) that
is fully OIDC-compliant.

This is a pure configuration addition — no architectural changes are needed. The
multi-provider infrastructure introduced in `feature/expand-oauth2-providers`
(issue `20260226-2020`) supports any standard OIDC provider by adding ~10 lines
to `provider.rs`.

Primary goal: verify the provider system works correctly with a third OIDC
provider and a self-hosted IdP.

## Related Issues

- `20260226-2020` Expand OAuth2 Provider Support (depends on: provider
  infrastructure from Step 1 of that issue)

## Approach

Keycloak is fully OIDC-compliant. The issuer URL format is
`http(s)://{host}/realms/{realm-name}`. Discovery document is available at
`{issuer}/.well-known/openid-configuration`.

For local development, Keycloak can be started with a single Docker command:

```bash
docker run -p 8180:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Then configure a realm and a confidential client via the Admin Console at
`http://localhost:8180`.

For demo-live (Cloud Run), use Keycloak Cloud (free tier) or any other
publicly accessible Keycloak instance.

### Required env vars

```
OAUTH2_KEYCLOAK_CLIENT_ID=<client-id>
OAUTH2_KEYCLOAK_CLIENT_SECRET=<client-secret>
OAUTH2_KEYCLOAK_ISSUER_URL=http://localhost:8180/realms/<realm-name>
```

`OAUTH2_KEYCLOAK_RESPONSE_MODE` defaults to `form_post`; set to `query` if
needed.

## Related Files

- `oauth2_passkey/src/oauth2/provider.rs` — add `Keycloak` variant + static
- `dot.env.example` — add Keycloak example block
- `demo-live/env.cloud-run.yaml` — add if enabling on demo-live
- `demo-live/DEPLOY.md` — add Keycloak setup notes if enabling on demo-live

## Implementation Tasks

### Code changes (`provider.rs`)

- [ ] Add `Keycloak` variant to `ProviderKind` enum
- [ ] Add `KEYCLOAK_PROVIDER: LazyLock<Option<ProviderConfig>>` static (reads `OAUTH2_KEYCLOAK_CLIENT_ID`, `OAUTH2_KEYCLOAK_CLIENT_SECRET`, `OAUTH2_KEYCLOAK_ISSUER_URL`)
- [ ] Add `ProviderKind::Keycloak` arm to `provider_for` match
- [ ] Add `"keycloak"` arm to `ProviderKind::from_path_segment`

### Configuration

- [ ] Add Keycloak example block to `dot.env.example`
- [ ] Set up local Keycloak via Docker, create realm and confidential client
- [ ] Configure `.env` with `OAUTH2_KEYCLOAK_*` settings
- [ ] Run demo-oauth2 locally, verify Auth0 + Google + Keycloak buttons appear
- [ ] Log in via Keycloak, verify DB row has `provider="keycloak"` and correct `sub`
- [ ] Verify Google and Auth0 logins still work concurrently

### Optional: demo-live

- [ ] Decide whether to enable Keycloak on demo-live (requires publicly accessible instance)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Created as standalone issue

- Context: After completing Auth0 support (issue `20260226-2020` Step 2),
  user wanted to add the next easiest OIDC provider. Keycloak was selected
  as the most accessible option (self-hostable via Docker, no external account
  required, full OIDC compliance).
- Decision: Create a new issue rather than extending `20260226-2020`, since the
  architectural work is complete and each additional provider is an independent
  deliverable.
- Reason: Keeps issue scope focused; `20260226-2020` can remain open for
  Phase 2 (GitHub non-OIDC) and Phase 3 (Apple) which require new abstractions.

## Resolution
