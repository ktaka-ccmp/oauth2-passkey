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

## Closed: 2026-04-20

## Status: completed

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

For local development, a `docker-compose.yaml` is provided in `idp/keycloak/`:

```bash
cd idp/keycloak
docker compose up -d
```

Admin Console is at `http://localhost:8180` (admin/admin). Data is persisted in
a named Docker volume (`keycloak-data`). Configure a realm and a confidential
client via the Admin Console.

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

- `oauth2_passkey/src/oauth2/provider.rs` — `Keycloak` variant + static
- `oauth2_passkey/src/oauth2/provider/tests.rs` — parse test for `"keycloak"`
- `oauth2_passkey_axum/src/oauth2.rs` — `"keycloak"` arm in `provider_view()`
- `oauth2_passkey_axum/static/o2p-base.css` — `.btn-keycloak` styles
- `dot.env.example` — Keycloak example block
- `idp/keycloak/docker-compose.yaml` — local dev Keycloak setup
- `demo-live/env.cloud-run.yaml` — add if enabling on demo-live
- `demo-live/DEPLOY.md` — add Keycloak setup notes if enabling on demo-live

## Implementation Tasks

### Code changes (`provider.rs`)

- [x] Add `Keycloak` variant to `ProviderKind` enum
- [x] Add `KEYCLOAK_PROVIDER: LazyLock<Option<ProviderConfig>>` static (reads `OAUTH2_KEYCLOAK_CLIENT_ID`, `OAUTH2_KEYCLOAK_CLIENT_SECRET`, `OAUTH2_KEYCLOAK_ISSUER_URL`)
- [x] Add `ProviderKind::Keycloak` arm to `provider_for` match
- [x] Add `"keycloak"` arm to `ProviderKind::from_path_segment`

### Configuration

- [x] Add Keycloak example block to `dot.env.example`
- [x] Set up local Keycloak via Docker, create realm and confidential client
- [x] Configure `.env` with `OAUTH2_KEYCLOAK_*` settings
- [x] Run demo-oauth2 locally, verify Auth0 + Google + Keycloak buttons appear
- [x] Log in via Keycloak, verify DB row has `provider="keycloak"` and correct `sub`
- [x] Verify Google and Auth0 logins still work concurrently

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

### 2026-04-20: form_post works on localhost (no need for query mode)

- Context: Initial plan noted that `OAUTH2_KEYCLOAK_RESPONSE_MODE=query` may
  be needed for localhost HTTP because `form_post` requires `Secure` cookies.
- Decision: No special response_mode setting required; leave at default `form_post`.
- Reason: Chrome treats `localhost` as a secure context, so `__Host-CsrfId`
  with `Secure` + `SameSite=None` is accepted even over plain HTTP localhost.
  Verified by successful login with the default `form_post` mode.

### 2026-04-20: Use docker compose with named volume instead of bare docker run

- Context: Initial approach used `docker run` without a volume, making data
  volatile. First attempt at a bind mount (`./data`) caused
  `AccessDeniedException` because the container's non-root user (UID 1000)
  could not write to the host-owned directory.
- Decision: Added `idp/keycloak/docker-compose.yaml` using a named Docker
  volume (`keycloak-data`).
- Reason: Named volumes are managed by Docker with correct permissions set
  automatically. Data persists across `docker compose down / up` cycles.

## Resolution

Keycloak added as a third optional OIDC provider. Enabled by setting
`OAUTH2_KEYCLOAK_CLIENT_ID`, `OAUTH2_KEYCLOAK_CLIENT_SECRET`, and
`OAUTH2_KEYCLOAK_ISSUER_URL`. Verified end-to-end locally with DB row
`provider="keycloak"`, `provider_user_id="keycloak_<UUID>"`. Google and Auth0
regressions confirmed passing. Local dev setup documented in
`idp/keycloak/docker-compose.yaml`.
