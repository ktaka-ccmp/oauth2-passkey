# Session Snapshot: Documentation & Demo Apps

**Date**: 2026-01-26

## Context

Part of library user documentation improvement effort. Custom Page customization for login, summary, and admin pages is complete with working demo. Demo apps for database patterns are done.

## Completed This Session

1. Updated demo-profile database configuration to be neutral (both same-DB and separate-DB presented as valid options)
2. Created demo-todo application demonstrating 1:N relationship with full CRUD operations
3. Added User Data Integration documentation to mdbook
4. Added Custom Admin Page documentation and re-exports
5. Added custom admin pages to demo-custom-login (admin_list.j2, admin_user.j2)

## Files Modified

### demo-custom-login updates

- `demo-custom-login/src/main.rs` - Added admin handlers (admin_list, admin_user), updated templates with is_admin
- `demo-custom-login/templates/admin_list.j2` (NEW) - Custom admin user list page
- `demo-custom-login/templates/admin_user.j2` (NEW) - Custom admin user detail page
- `demo-custom-login/templates/index_user.j2` - Added admin link for admin users
- `demo-custom-login/templates/summary.j2` - Added admin link for admin users
- `demo-custom-login/README.md` - Updated with admin pages documentation

### demo-todo (NEW)

- `demo-todo/Cargo.toml`
- `demo-todo/.env.example`
- `demo-todo/src/main.rs` - AppState, index handler with todo list
- `demo-todo/src/db.rs` - Todo struct, CRUD operations (list, create, toggle, delete)
- `demo-todo/src/handlers.rs` - POST routes for create/toggle/delete
- `demo-todo/src/server.rs` - HTTP/HTTPS server setup
- `demo-todo/templates/index.j2` - Todo list UI with add form
- `demo-todo/README.md`
- `demo-todo/self_signed_certs/gen_certs.sh`
- `Cargo.toml` - Added demo-todo to workspace members

### Documentation

- `docs/src/integration/user-data.md` (NEW) - User Data Integration guide (1:1 and 1:N patterns)
- `docs/src/integration/custom-pages.md` (UPDATED) - Added Custom Admin Page section, Feature Flags
- `docs/src/SUMMARY.md` - Added user-data.md to Part 2

### Library Updates

- `oauth2_passkey_axum/src/lib.rs` - Added admin re-exports: `DbUser`, `SessionId`, `CredentialId`, `ProviderUserId`, `get_all_users`, `get_user`, `update_user_admin_status`, `delete_user_account_admin`, `delete_passkey_credential_admin`, `delete_oauth2_account_admin`

### demo-profile updates

- `demo-profile/.env.example` - Simplified database configuration section
- `demo-profile/README.md` - Database Configuration section without "Recommended" labels
- `db/postgresql/docker-compose.yaml` - Changed database name from "passkey" to "demo"
- `demo-profile/src/db.rs` - Updated default URL

## Upcoming Task Queue

| Priority | Task | Category |
| -------- | ---- | -------- |
| ~~1~~ | ~~Create demo-todo (1:N pattern with full CRUD)~~ | ~~Demo App~~ |
| ~~2~~ | ~~Add DB documentation to mdbook~~ | ~~Documentation~~ |
| ~~3~~ | ~~Admin menu customization~~ | ~~Custom Page~~ |
| 4 | Improve other documentation readability | Documentation |
| 5 | Review ToDo.md | Planning |
| 6 | Improve library's default design | UI/UX |
| 7 | Fix Windows TPM attestation bug | Bug Fix |

## Key Decisions

1. **Two Demo Patterns**: demo-profile (1:1) and demo-todo (1:N) cover common database relationship patterns

2. **Neutral Database Options**: Both same-database and separate-database setups presented as equally valid

3. **Standard Axum Pattern for User Apps**: Demo apps use `State<AppState>` pattern (best practice)

4. **Documentation Structure**: User Data Integration added to Part 2 (Basic Integration) in mdbook

5. **Admin Customization in demo-custom-login**: Added to existing demo rather than creating new one for consistency

6. **Re-exports Always Available**: Admin/summary re-exports kept always available (not feature-gated) with documentation comments for guidance. Feature-gating would create confusing inverse relationship (disable admin-ui → need admin re-exports).

## Admin Page Customization Notes

- **Feature Flags**: `admin-ui` and `user-ui` can be disabled independently
- **Admin Functions**: All require admin privileges (checked via `has_admin_privileges()`)
- **First User Protection**: sequence_number=1 user cannot have admin status changed
- **Re-exports Added**: `DbUser`, `SessionId`, `CredentialId`, `ProviderUserId` + 6 admin functions
- **Demo Routes**: `/admin` (user list), `/admin/user/{id}` (user detail)
