# Issue: Remove sequence_number=1 Special-Casing from has_admin_privileges()

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260213-1500

## Created: 2026-02-13-15-00

## Closed: 2026-02-13

## Status: wontfix

## Priority: low

## Difficulty: medium

## Description

The `has_admin_privileges()` method currently returns `self.is_admin || self.sequence_number == Some(1)`,
meaning the first user always has admin privileges regardless of the `is_admin` field. This creates
a dual source of truth for admin status:

1. `is_admin` field (the intended admin flag)
2. `sequence_number == 1` (a bootstrap backdoor)

The `sequence_number == 1` backdoor was originally a safety net, but with the last-admin guard
(issue 20260210-1930) and unconditional first-user demotion protection now in place, the backdoor
is no longer needed for safety.

### Current Behavior

- First user (seq=1) with `is_admin=false`: `has_admin_privileges()` returns true (via seq=1)
- "Demoting" the first user sets `is_admin=false` but does not actually remove privileges
- SQL `count_admin_users` uses `WHERE is_admin = true OR sequence_number = 1`

### Desired Behavior

- `has_admin_privileges()` returns `self.is_admin` only
- `count_admin_users` SQL uses `WHERE is_admin = true` only
- `is_admin` is the sole source of truth for admin privileges
- Upsert auto-promotion (seq=1 -> is_admin=true) remains as bootstrap mechanism

## Related Issues

- `20260210-1930` Admin Deletion Safeguard (parent: added last-admin guard and first-user demotion protection)

## Approach

1. Change `has_admin_privileges()` to `self.is_admin` only (3 implementations)
2. Change SQL count queries to `WHERE is_admin = true` only
3. Remove seq=1 special-casing from admin UI templates
4. Update tests for `has_admin_privileges()` (session/types, userdb/types)
5. Update documentation (api/axum.md, customizing-templates.md, demo READMEs, Readme.md)
6. Keep upsert auto-promotion (seq=1 -> is_admin=true) as initial bootstrap

## Related Files

- `oauth2_passkey/src/session/types.rs` (has_admin_privileges)
- `oauth2_passkey/src/userdb/types.rs` (has_admin_privileges)
- `oauth2_passkey_axum/src/session.rs` (AuthUser::has_admin_privileges)
- `oauth2_passkey/src/userdb/storage/sqlite.rs` (count_admin_users SQL)
- `oauth2_passkey/src/userdb/storage/postgres.rs` (count_admin_users SQL)
- `oauth2_passkey_axum/templates/admin_index.j2` (seq=1 UI special-casing)
- `oauth2_passkey_axum/templates/admin_user_page.j2` (seq=1 UI special-casing)
- `oauth2_passkey/src/session/types/tests.rs` (has_admin_privileges tests)
- `oauth2_passkey/src/userdb/types/tests.rs` (has_admin_privileges tests)
- `docs/src/api/axum.md` (documentation)
- `docs/src/integration/customizing-templates.md` (documentation)
- `demo-both/README.md`, `demo-oauth2/README.md`, `demo-custom-login/README.md` (docs)
- `Readme.md` (documentation)

## Implementation Tasks

- [ ] Change `has_admin_privileges()` to `self.is_admin` only (session/types.rs, userdb/types.rs, session.rs)
- [ ] Change SQL count queries to `WHERE is_admin = true` only (sqlite.rs, postgres.rs)
- [ ] Remove seq=1 special-casing from admin UI templates (admin_index.j2, admin_user_page.j2)
- [ ] Update tests for has_admin_privileges (session/types/tests.rs, userdb/types/tests.rs)
- [ ] Update documentation (api/axum.md, customizing-templates.md, demo READMEs, Readme.md, ToDo.md)
- [ ] Verify first-user demotion guard still works correctly after the change

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-13: Deferred from admin safeguard issue

- Context: During admin safeguard implementation (issue 20260210-1930), discovered that
  `has_admin_privileges()` includes `sequence_number == 1` as a backdoor, creating a dual
  source of truth for admin privileges
- Decision: Defer to separate issue because the scope (18 files across code, tests, templates,
  and docs) significantly exceeds the admin safeguard issue
- Reason: The admin safeguard is complete and safe with the current approach (first-user
  unconditionally protected from demotion + last-admin guard for others). The seq=1 removal
  is a design improvement, not a safety fix

### 2026-02-13: Closed as wontfix -- current design is a sensible default

- Context: After completing the admin safeguard implementation (issue 20260210-1930), realized
  that the first-user (seq=1) special-casing in `has_admin_privileges()` actually serves as a
  useful default behavior for library users
- Decision: Close as wontfix. The `sequence_number == 1` check in `has_admin_privileges()` is
  not a problem to fix but a feature to keep
- Reason: The current design provides a sensible default with a clean escape hatch:
  1. First user is automatically admin and cannot be demoted (convenient default)
  2. If a library user does not want this behavior, they can simply have the first user delete
     themselves after creating another admin
  3. After first-user deletion, all remaining admins are equal and protected only by the
     last-admin guard
  4. This gives library users flexibility without requiring code changes
- The dual source of truth (is_admin + seq=1) is intentional: seq=1 provides the bootstrap
  guarantee, is_admin provides the operational admin flag. They serve different purposes

## Resolution

Closed as wontfix. The `sequence_number == 1` special-casing in `has_admin_privileges()` is a
deliberate design choice that provides a sensible default for library users. The first user is
always admin and cannot be demoted, giving a stable bootstrap guarantee. Library users who prefer
all admins to be equal can have the first user self-delete after promoting another admin, at which
point all admins are protected equally by the last-admin guard (issue 20260210-1930). No code
changes needed.
