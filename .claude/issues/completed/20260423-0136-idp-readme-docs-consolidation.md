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

## Closed: 2026-05-05

## Status: completed

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

- [x] Audit `idp/README.md` sections — classify each as "keep in README" vs "move to docs"
- [x] ~~Create `docs/src/guides/zitadel.md` with Zitadel setup walkthrough~~ (not needed — `generic-oidc.md` already has it)
- [x] ~~Create `docs/src/guides/ory-hydra.md` with Ory Hydra setup walkthrough~~ (not needed — `generic-oidc.md` already has it)
- [x] ~~Update `docs/src/guides/keycloak.md` with content from `idp/README.md` §Keycloak~~ (not needed — `idp/README.md` had no Keycloak walkthrough; existing `keycloak.md` is sufficient)
- [x] Trim `idp/README.md` to quick-reference only (stack table + up/down + credential reset)
- [x] Add cross-links from `idp/README.md` to the new guide pages
- [x] ~~Update `docs/src/SUMMARY.md` to include new guide pages~~ (no new pages added; `generic-oidc.md` already in SUMMARY)
- [x] Verify no broken links / anchors
- [x] Audit `docs/src/guides/generic-oidc.md` for outdated OIDC configuration descriptions (preset system, Named vs Custom slot distinction, env var examples) — the guide predates the `PRESET=` mechanism and may still describe manual `DISPLAY_NAME`/`NAME`/`BUTTON_COLOR` setup as the only option

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

### 2026-05-05: One-way consolidation into generic-oidc.md (not new per-IdP pages)

- Context: Investigation showed `docs/src/guides/generic-oidc.md` already
  contained full setup walkthroughs for Zitadel, Ory Hydra, Authentik, and
  Okta — not just env var examples. The original plan to create
  `zitadel.md` and `ory-hydra.md` would have duplicated existing content.
- Decision: Treat the work as **one-way consolidation into
  `generic-oidc.md`** (canonical) rather than 50/50 split. Trim
  `idp/README.md` to operator quick-reference (~180 lines) with
  cross-links into `generic-oidc.md`. No new guide pages, no
  `SUMMARY.md` change.
- Reason: Less duplication, fewer files to keep in sync, and the
  walkthroughs were already in their natural home.

### 2026-05-05: Step 1 verification finding

- Context: Before trimming, compared every section of `idp/README.md`
  with `generic-oidc.md` to confirm what was unique.
- Decision: Promoted these unique items into `generic-oidc.md` before
  removal:
  - Zitadel "CODE vs PKCE auth method" warning (was in `idp/README.md`
    §1.2; would prevent silent registration mistakes for any reader of
    `generic-oidc.md`).
  - Hydra `RESPONSE_MODE=query` requirement in the Step 3 env-var block
    (`generic-oidc.md` had the discovery section but not the env-var
    note).
  - Three troubleshooting entries: Hydra `form_post` (folded into the
    existing Zitadel `form_post` entry), Zitadel login-loop, JWKS stale
    after switching IdP versions.
  - End-to-End Verification section (`sqlite3 ...` snippet for DB
    verification).
- Reason: Confirmed that walkthroughs in `generic-oidc.md` cover the
  same ground at equivalent or better detail; only operationally-pure
  content (Docker compose commands, openssl secret-gen step, IAM Owner
  log retrieval) remains exclusive to `idp/README.md`.

## Resolution

Consolidation complete. `idp/README.md` is now ~180 lines of pure
operator quick-reference (stack table, prerequisites, per-stack
up/down/wipe blocks, JWKS cache reset). All detailed walkthroughs and
troubleshooting live in `docs/src/guides/generic-oidc.md`, with
GitHub-relative cross-links from `idp/README.md`.

### What changed

- `idp/README.md`: 675 → 180 lines (-73%). Added Authentik to the
  stack table; added Keycloak operational block.
- `docs/src/guides/generic-oidc.md`: 837 → 929 lines (+11%). Added
  E2E Verification section, 2 new troubleshooting entries (login-loop,
  JWKS-stale-cache), Hydra `form_post` paragraph appended to existing
  Zitadel entry, Zitadel CODE-vs-PKCE warning, Hydra
  `RESPONSE_MODE=query` env-var note. Updated Zitadel/Authentik/Okta
  Step 3 examples to lead with `PRESET=`.
- No `docs/src/SUMMARY.md` change (no new pages).
