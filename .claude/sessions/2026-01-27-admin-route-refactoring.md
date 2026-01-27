# Admin Route Refactoring Plan

## Current Task

Refactoring admin routes and handler names for better clarity and intuitive naming.

## Completed in This Session

1. **Responsive Mobile Layout for Admin User List** (committed: d6ac49a)
   - Transform table to card layout on mobile (<=600px)
   - Added data-label attributes for mobile field labels
   - Text truncation with ellipsis for long content

2. **Moved list_users from default.rs to optional.rs** (committed: da4750b)
   - API endpoints remain in `default.rs` (always available)
   - UI pages moved to `optional.rs` (controlled by `admin-ui` feature)

3. **Route and Handler Renaming** (READY TO COMMIT)
   - Route: `/list_users` -> `/`
   - Handler: `list_users()` -> `admin_index()`
   - Handler: `user_summary()` -> `admin_user_page()`
   - Template: `UserListTemplate` -> `AdminIndexTemplate`
   - Template: `UserSummaryTemplate` -> `AdminUserPageTemplate`
   - Config: `O2P_ADMIN_URL` default `/o2p/admin/list_users` -> `/o2p/admin/`
   - Added fallback redirect: `/admin` -> `/admin/` (trailing slash fix)

4. **Page Title and Link Text Updates** (READY TO COMMIT)
   - Page title: "User List" -> "User Management" in admin_user_list.j2
   - Link text: "User List" -> "Admin" in summary.j2

5. **Documentation Updates** (READY TO COMMIT)
   - Updated all URL references in documentation
   - Updated template links in admin_user.j2 and summary.j2
   - Updated templates.md and customizing-templates.md

## Files Modified (Ready to Commit)

| File | Changes |
|------|---------|
| `oauth2_passkey_axum/src/admin/optional.rs` | Route and handler renaming, template struct renaming |
| `oauth2_passkey_axum/src/config.rs` | O2P_ADMIN_URL default updated |
| `oauth2_passkey_axum/src/router.rs` | Added fallback handler for trailing slash redirect |
| `oauth2_passkey_axum/templates/admin_user.j2` | Go Back link updated |
| `oauth2_passkey_axum/templates/admin_user_list.j2` | Title and heading: "User List" -> "User Management" |
| `oauth2_passkey_axum/templates/summary.j2` | Link text: "User List" -> "Admin" |
| `oauth2_passkey_axum/README.md` | Endpoint documentation updated |
| `docs/src/getting-started/quick-start.md` | URL references updated |
| `docs/src/integration/customizing-css.md` | URL references updated |
| `docs/src/integration/customizing-templates.md` | URL references and defaults updated, "User List" -> "User Management" |
| `docs/src/integration/framework.md` | URL references updated |
| `docs/src/integration/templates.md` | URL reference updated |
| `demo-both/README.md` | URL reference updated |

## Technical Notes

### Trailing Slash Handling

Axum's `.nest("/admin", ...)` doesn't match `/admin` (without trailing slash). Attempted solutions:
1. ~~Add `.route("/admin", ...)` for redirect~~ - Caused "Overlapping method route" panic
2. **Used fallback handler** - Added `trailing_slash_redirect()` function in router.rs that redirects `/admin` to `/admin/`

This ensures both `/o2p/admin` and `/o2p/admin/` work correctly.

### Naming Changes Summary

| Location | Before | After |
|----------|--------|-------|
| Route | `/list_users` | `/` |
| Handler | `list_users()` | `admin_index()` |
| Handler | `user_summary()` | `admin_user_page()` |
| Template struct | `UserListTemplate` | `AdminIndexTemplate` |
| Template struct | `UserSummaryTemplate` | `AdminUserPageTemplate` |
| Page title | "User List" | "User Management" |
| Nav link text | "User List" | "Admin" |

## Next Steps

1. [x] Commit all changes: "refactor(axum): rename admin routes and templates for clarity" (19548fe)
2. [x] Manual testing with demo-both
3. [ ] Push to origin (4 commits ahead)

## Observation: O2P_REDIRECT_ANON Naming Confusion

The `O2P_REDIRECT_ANON` configuration variable has confusing semantics:
- **Name implies**: Redirect destination for anonymous/unauthenticated users
- **Actual usage**: Also used to redirect already-logged-in users when they visit the login page

This dual usage creates confusion. Potential improvements:
1. Rename to `O2P_REDIRECT_DEFAULT` or `O2P_HOME_URL`
2. Split into separate variables for different use cases
3. Clarify in documentation

## Context

- Currently on `dev` branch, 3 commits ahead of origin
- Breaking change is acceptable (pre-release dev stage)
- `demo-custom-login` uses custom admin implementation, unaffected by library changes
