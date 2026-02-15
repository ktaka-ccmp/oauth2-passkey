# Issue: Documentation Improvement Planning

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-24-01

## Created: 2026-01-24

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Plan improvements to mdBook user guide documentation. Originally started as a general
review, now includes specific documentation gaps identified from the CHANGELOG analysis
of all changes since v0.2.0.

### Documentation Gaps (identified 2026-02-16)

Comparison of CHANGELOG [Unreleased] entries against current docs (`docs/src/`) revealed
the following items that are not yet documented:

#### New Admin API Endpoints (not in API reference)

- `GET /admin/audit` - Cross-user audit page with date filtering
- `GET /admin/user/{user_id}/login_history` - Per-user login history
- `GET /admin/sessions` - Active sessions list
- `POST /admin/user/{user_id}/logout` - Force logout a user

#### New Environment Variables (not in configuration docs)

- `O2P_PASSKEY_PROMOTION` (`ask`/`force`) - Passkey registration promotion after OAuth2 login
- `O2P_DEMO_MODE` - Demo mode (all users get admin, sensitive data masked)

#### New Features (not documented)

- `bundled-tls` feature flag - Bundles Mozilla root certificates for scratch/alpine Docker images
- Admin safeguards - Prevent deleting/demoting the last admin user, self-deletion protection
- `getClientCapabilities()` JavaScript helper for WebAuthn feature detection

### Documentation Structure

1. Getting Started - Introduction, Quick Start, Architecture
2. Integration Guide - Framework setup, OAuth2/Passkey JS APIs, Configuration
3. Security - Security model, CSRF, Sessions, Production deployment
4. WebAuthn Reference - Attestation formats
5. Platform Compatibility - iOS Safari specifics
6. API Reference - Core library and Axum integration
7. Maintainer Guide - Development, CI/CD, Release
8. Appendices - Security advisories, Troubleshooting

## Related Issues

- `2026-02-09-01` Update CHANGELOG.md for Changes Since v0.2.0 (related to: gaps identified during changelog review)

## Approach

Update documentation in priority order:
1. API reference (`api/axum.md`) - Add missing admin endpoints
2. Configuration (`integration/configuration.md`) - Add missing env vars
3. Feature documentation - `bundled-tls`, admin safeguards, `getClientCapabilities()`

## Related Files

- `docs/src/` - mdBook documentation
- `docs/src/SUMMARY.md` - Documentation structure
- `docs/src/api/axum.md` - Axum API reference (needs new admin endpoints)
- `docs/src/integration/configuration.md` - Configuration reference (needs new env vars)
- `docs/src/integration/passkey-js.md` - Passkey JS API (needs `getClientCapabilities()`)
- `docs/src/integration/server-setup.md` - Server setup (needs `bundled-tls`)

## Implementation Tasks

### Gap filling: Reflect CHANGELOG [Unreleased] changes in docs

- [ ] Add login history and force logout endpoints to `api/axum.md`
  - `/sessions` (GET), `/user/{user_id}/logout` (POST)
  - `/user/{user_id}/login_history` (GET), `/audit` (GET), `/audit_page` (GET)
  - Query params: `limit`, `offset`, `from`, `to`, `tz_offset`, `user_id`, `success`
  - Admin safeguards note (last admin protection, self-deletion prevention)
- [ ] Add `O2P_PASSKEY_PROMOTION` and `O2P_DEMO_MODE` to `integration/configuration.md`
  - `O2P_PASSKEY_PROMOTION`: `ask`/`force`/unset, passkey registration after OAuth2 login
  - `O2P_DEMO_MODE`: `true`/`false`, auto-admin, data masking, placeholder user
- [ ] Add `bundled-tls` feature flag to `integration/server-setup.md`
  - Purpose: bundles `webpki-roots` for scratch/alpine Docker images
  - Cargo.toml example, Dockerfile example
- [ ] Add `getClientCapabilities()` to `integration/passkey-js.md`
  - `initPasskeyCapabilities()`, `hasSignalCapability(name)`
  - Browser support notes

### General readability improvements

- [ ] Review and improve selected sections (requires user input)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-24: Deferred

- Context: Documentation improvement session started, structure reviewed
- Decision: Defer; user prioritized Signal API implementation instead
- Reason: Other work had higher priority at the time

### 2026-02-16: Reopened with specific gaps from CHANGELOG review

- Context: CHANGELOG [Unreleased] update (issue 2026-02-09-01) revealed documentation gaps
- Decision: Add specific tasks for undocumented features/endpoints/env vars
- Reason: CHANGELOG analysis provided a concrete list of what is missing from docs

## Resolution

