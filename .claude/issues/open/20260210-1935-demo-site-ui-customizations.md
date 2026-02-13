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
- [x] Custom login page for demo-live (2-button layout)
- [x] Refactor: consolidate O2P_DEMO_MODE into Masker struct with per-type masked() methods
- [x] Improve O2P_DEMO_MODE env var documentation
- [x] OAuth2-only first user creation (addressed by login page UI design, no API-level gate needed)
- [x] Test all customizations on passkey-demo.ccmp.jp
- [ ] Simplify demo-live: remove developer demo pages (p1-p6), simplify home page
- [ ] Add GitHub repository link to demo-live pages

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

### 2026-02-14: Masker struct refactor instead of migrating admin UI to demo-live

- Context: Phase 2 plan proposed moving all admin UI and masking code from
  library to demo-live with feature flags (admin-api, admin-ui, user-ui)
- Decision: Keep masking code in library, consolidate O2P_DEMO_MODE checks
  into a Masker struct instead
- Reason: Phase 2 would duplicate ~500 lines of admin handlers in demo-live,
  creating maintenance burden (changes needed in two places). Masker struct
  achieved the main goal (O2P_DEMO_MODE references: 4 places/3 files -> 2
  places/1 file) with minimal change (4 files, 1 commit). Phase 2 migration
  can be revisited if library needs to be fully demo-mode-free for publishing.

### 2026-02-14: OAuth2-only first user via UI design, not API gate

- Context: Whether to add API-level enforcement for OAuth2-only first user creation
- Decision: Rely on custom login page UI (no passkey registration button) instead
- Reason: Adding API-level gate would increase O2P_DEMO_MODE footprint in core
  library, contradicting the goal of minimal library pollution. Login page design
  effectively achieves OAuth2-first without any library changes.

## Resolution

All demo site UI/UX customizations implemented and deployed. Key deliverables:
- O2P_DEMO_MODE env var controlling admin defaults and data masking
- Masker struct centralizing all masking logic (2 O2P_DEMO_MODE references in 1 file)
- Custom login page for demo-live (2-button layout, no passkey registration)
- Backend masking for admin index, user detail, audit log, and login history
- Verification on passkey-demo.ccmp.jp
