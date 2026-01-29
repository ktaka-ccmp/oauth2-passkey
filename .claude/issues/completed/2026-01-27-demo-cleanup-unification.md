# Issue: Demo Cleanup & Unification

## ID: 2026-01-27-03

## Status: completed

## Priority: medium

## Description

Demo application cleanup: naming consistency, configuration improvements, and router API unification across all 6 demo apps.

## Related Files

- `demo-custom-login/` - Renamed templates (summary->account, admin_list->admin_index)
- `demo-profile/src/db.rs` - APP_DATABASE_URL enforcement
- `demo-todo/src/db.rs` - APP_DATABASE_URL enforcement
- `demo-oauth2/src/main.rs` - Router API unification

## Notes

Commits:
- `cd90526` refactor(demo): rename summary->account, admin_list->admin_index
- `c7aa549` refactor(demo): require APP_DATABASE_URL instead of silent fallback
- `e474690` refactor(demo): use oauth2_passkey_full_router in demo-oauth2

Key decisions:
1. demo-custom-login inline CSS intentional (demonstrates UI independence)
2. APP_DATABASE_URL should error, not fallback silently
3. All demos unified on `oauth2_passkey_full_router()`

## Resolution

Completed 2026-01-27. All demo apps unified with consistent naming and configuration.
