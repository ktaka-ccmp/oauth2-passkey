# Issue: Consolidate idp/README.md into docs/

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260423-0136

## Created: 2026-04-23-01-36

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

`idp/README.md` has grown to 674 lines, mixing two concerns:
1. Quick operator commands (Docker Compose up/down, credential reset)
2. Detailed per-IdP client registration walkthroughs (step-by-step with screenshots/code)

`docs/src/guides/` already hosts per-provider guides (`auth0.md`, `keycloak.md`, `generic-oidc.md`), but
does not cover the self-hosted IdP setup side. This consolidation moves the detailed content to `docs/`
and leaves `idp/README.md` as a lean operator quick-reference.

## Related Issues

- `2026-01-24-01` Documentation Improvement Planning (related)

## Approach

**`idp/README.md` after trim**: Keep only:
- Stack table (one line per IdP with Docker Compose directory + issuer URL)
- `docker compose up/down` commands per IdP
- Admin credential reset one-liners

**`docs/src/guides/`**: Add new pages (or extend existing) for each self-hosted IdP:
- `docs/src/guides/zitadel.md` — full setup walkthrough (currently in idp/README.md §1)
- `docs/src/guides/ory-hydra.md` — Hydra + Kratos walkthrough (§2)
- `docs/src/guides/keycloak.md` — extend existing (§3), or link to existing guide
- Cross-link from `idp/README.md` to the corresponding guide page for the detailed steps

Update `docs/src/SUMMARY.md` to include new guide pages.

## Related Files

- `idp/README.md`
- `docs/src/guides/generic-oidc.md`
- `docs/src/guides/keycloak.md`
- `docs/src/guides/zitadel.md` (new)
- `docs/src/guides/ory-hydra.md` (new)
- `docs/src/SUMMARY.md`

## Implementation Tasks

- [ ] Audit `idp/README.md` sections — classify each as "keep in README" vs "move to docs"
- [ ] Create `docs/src/guides/zitadel.md` with Zitadel setup walkthrough
- [ ] Create `docs/src/guides/ory-hydra.md` with Ory Hydra setup walkthrough
- [ ] Update `docs/src/guides/keycloak.md` with content from `idp/README.md` §Keycloak
- [ ] Trim `idp/README.md` to quick-reference only (stack table + up/down + credential reset)
- [ ] Add cross-links from `idp/README.md` to the new guide pages
- [ ] Update `docs/src/SUMMARY.md` to include new guide pages
- [ ] Verify no broken links / anchors
- [ ] Audit `docs/src/guides/generic-oidc.md` for outdated OIDC configuration descriptions (preset system, Named vs Custom slot distinction, env var examples) — the guide predates the `PRESET=` mechanism and may still describe manual `DISPLAY_NAME`/`NAME`/`BUTTON_COLOR` setup as the only option

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-23: Scope defined

- Context: `idp/README.md` grown to 674 lines; user proposed splitting operational quick-reference from detailed walkthrough
- Decision: Trim `idp/README.md` to Docker Compose commands + credential reset only; move detailed per-IdP setup into `docs/src/guides/`
- Reason: `docs/src/guides/` is already the home for per-provider guides (auth0, keycloak, generic-oidc); keeping operational detail there avoids duplicating context

### 2026-05-05: Add OIDC config documentation audit task

- Context: The `PRESET=` mechanism (auth0, keycloak, entra, zitadel, okta, authentik, line) now supplies display_name, name, icon_slug, and button colors automatically. `generic-oidc.md` and other guides may still describe manual env var setup as the primary path, and the Named vs Custom slot distinction has evolved since the guides were written.
- Decision: Add a task to audit OIDC configuration documentation for accuracy when this issue is worked on.
- Reason: Avoids users following outdated setup instructions that require unnecessary env vars.

## Resolution
