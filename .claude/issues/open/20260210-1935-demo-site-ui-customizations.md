# Issue: Demo Site UI/UX Customizations

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260210-1935

## Created: 2026-02-10-19-35

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

The public demo site needs several UI/UX customizations to be suitable for public
access. These changes should be implemented in the demo application layer (demo-live)
or via library configuration, without modifying core library internals.

### Requirements

1. **Admin/Normal user selection at creation**: Allow choosing admin or normal user
   role during OAuth2 account creation flow
2. **Field masking in user list**: Obscure Account and Label fields in the admin user
   list to protect user privacy on a public demo
3. **Audit log masking**: Hide or mask sensitive information in login history/audit logs
   (e.g., IP addresses, user agents)
4. **OAuth2-only first user creation**: Enforce that the initial user registration
   uses OAuth2 (not passkey-only), ensuring the user has a linked Google account

## Related Issues

- `2026-01-30-08` Demo Site Deployment (parent: these customizations are needed for the demo)
- `20260210-1930` Admin Deletion Safeguard (related: admin management improvements)

## Approach

### Strategy: Demo-app-side changes preferred

Prefer making changes in demo-live or via existing library configuration rather than
modifying core library code. This keeps the library clean and the demo customizations
isolated.

### Per-requirement approach

1. **Admin selection**: Add a post-registration hook in demo-live that calls
   `update_user_admin_status()` based on user choice, or add an environment variable
   to the library (e.g., `O2P_NEW_USER_DEFAULT_ADMIN=true`)
2. **Field masking**: CSS/JS changes in admin templates - mask Account/Label with
   asterisks or partial display
3. **Audit log masking**: Template-level filtering to hide or truncate IP addresses
   and user agent strings
4. **OAuth2-only first user**: Add env var `O2P_FIRST_USER_METHOD=oauth2` that gates
   passkey registration when no users exist

## Related Files

- `oauth2_passkey/src/config.rs` (O2P_DEMO_MODE definition)
- `oauth2_passkey/src/coordination/oauth2.rs` (OAuth2 user creation, is_admin from demo mode)
- `oauth2_passkey/src/coordination/passkey.rs` (Passkey user creation, is_admin from demo mode)
- `oauth2_passkey_axum/src/admin/masking.rs` (masking utility functions)
- `oauth2_passkey_axum/src/admin/default.rs` (admin API handlers with masking)
- `oauth2_passkey_axum/src/admin/optional.rs` (admin UI handlers with masking)
- `oauth2_passkey_axum/src/login_history.rs` (audit/login history with masking)
- `demo-live/src/main.rs` (demo application entry point)

## Implementation Tasks

- [x] Add `O2P_DEMO_MODE` env var (controls admin default + masking)
- [x] All new users get admin in demo mode (OAuth2 + Passkey creation)
- [x] Backend masking for admin_index (user list)
- [x] Backend masking for admin_user_page (user detail)
- [x] Backend masking for audit log / login history
- [x] Unit tests for masking functions
- [ ] Implement OAuth2-only gate for first user creation
- [ ] Test all customizations in Docker environment

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-10: Scope definition for demo UI customizations

- Context: Planning public demo site deployment, identified privacy and UX concerns
- Decision: Separate from deployment infrastructure issue, handle as dedicated UI/UX issue
- Reason: Different scope and skillset from Cloud Run deployment; keeps issues focused

### 2026-02-10: Demo-app-side changes preferred over library changes

- Context: Deciding whether to modify core library or demo application
- Decision: Prefer demo-app-side or configuration-based changes
- Reason: Keeps library clean for publishing; demo-specific customizations should not
  pollute the core library API

### 2026-02-14: Single O2P_DEMO_MODE replaces separate config variables

- Context: Designing admin default and masking for public demo site
- Decision: Use a single `O2P_DEMO_MODE=true` env var instead of separate
  `O2P_NEW_USER_DEFAULT_ADMIN` and masking toggles
- Reason: Prevents accidental misconfiguration in production. If admin default
  were a separate variable, someone could enable it without masking, exposing
  all users' data to every admin. Single toggle ensures both behaviors are
  always paired.

### 2026-02-14: Backend masking in Axum handlers, not core library

- Context: Choosing where to implement data masking (core lib vs Axum handlers)
- Decision: Mask data in Axum HTTP handlers before returning responses
- Reason: Core library stays clean (no demo-specific logic). Axum handlers
  receive raw data from the library and mask it server-side, so DevTools
  cannot see unmasked data. Same security as library-level masking.

### 2026-02-14: All admin operations allowed in demo mode

- Context: Whether to restrict admin operations (delete, force logout, etc.)
- Decision: Allow all operations; rely on existing admin safeguard protections
- Reason: Lets users experience the full admin feature set. Admin safeguard
  (PR #214) prevents last-admin deletion and first-user demotion, providing
  minimum safety guarantees.

## Resolution
