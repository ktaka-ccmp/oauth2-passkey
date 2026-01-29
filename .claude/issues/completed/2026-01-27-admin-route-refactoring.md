# Issue: Admin Route Refactoring

## ID: 2026-01-27-01

## Status: completed

## Priority: medium

## Description

Refactor admin routes and handler names for better clarity and intuitive naming.

## Related Files

- `oauth2_passkey_axum/src/admin/optional.rs` - Route and handler renaming
- `oauth2_passkey_axum/src/config.rs` - O2P_ADMIN_URL default updated
- `oauth2_passkey_axum/templates/admin_user_list.j2` - Title updated

## Notes

Changes made:
1. Responsive mobile layout for admin user list (table -> card on mobile)
2. Moved list_users from default.rs to optional.rs (controlled by `admin-ui` feature)
3. Route renaming: `/list_users` -> `/`
4. Handler renaming: `list_users()` -> `admin_index()`, `user_summary()` -> `admin_user_page()`
5. Template renaming: `UserListTemplate` -> `AdminIndexTemplate`
6. Config default: `O2P_ADMIN_URL` `/o2p/admin/list_users` -> `/o2p/admin/`
7. Page title: "User List" -> "User Management"

## Resolution

Completed 2026-01-27. Commits: d6ac49a, da4750b, 19548fe.
