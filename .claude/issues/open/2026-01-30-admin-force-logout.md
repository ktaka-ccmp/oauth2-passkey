# Issue: Admin Force Logout Feature

## ID: 2026-01-30-02

## Status: open

## Priority: medium

## Description

Add ability for administrators to force logout a specific user from the admin panel. This allows admins to invalidate all active sessions for a user when needed (e.g., security incident, account compromise, user request).

## Related Files

- `oauth2_passkey_axum/src/admin/` - Admin handlers
- `oauth2_passkey/src/session/main/user_sessions.rs` - User session mapping
- `oauth2_passkey/src/session/main/session.rs` - Session deletion
- `oauth2_passkey_axum/templates/admin_user.j2` - Admin user detail page

## Notes

**Use Cases**:
- Security incident response (compromised account)
- User requests logout from all devices
- Account suspension/termination
- Session cleanup for inactive users

**Implementation Approach**:

1. Add "Force Logout" button to admin user detail page (`admin_user.j2`)
2. Create POST endpoint `/o2p/admin/users/{user_id}/logout`
3. Use existing `user_sessions` mapping to find all session IDs
4. Delete all sessions for the user via `delete_session_from_store_by_session_id()`
5. Return success/failure response

**Dependencies**:
- Session Conflict Policy feature (`2026-01-28-02`) already implemented user->session mapping
- `user_sessions.rs` provides `get_user_sessions()` and mapping cleanup

**Security Considerations**:
- Endpoint must require admin privileges
- Should log the action for audit trail
- Consider CSRF protection for the action

---

## 2026-02-07 Update: Session Status Indicator

### Additional Feature
Add session status indicator to admin panel showing which users are currently logged in.

### Implementation Plan

**Phase 1: Core API**
1. Expose `cleanup_stale_sessions` via coordination layer as `get_active_session_count(user_id)`
2. Add bulk endpoint: `GET /o2p/admin/sessions` returning `{ user_id: session_count, ... }`

**Phase 2: Admin Index (User List)**
1. Add "Active" column to user table
2. JavaScript fetches session status after page load via bulk API
3. Display indicator (green dot for active, gray for inactive)

**Phase 3: Admin User Detail + Force Logout**
1. Show "Active Sessions: N" in user info section
2. Add "Force Logout" button (visible when N > 0)
3. POST `/o2p/admin/user/{user_id}/logout` to invalidate all sessions

### Files to Modify
- `oauth2_passkey/src/session/main/mod.rs` - Export session count function
- `oauth2_passkey/src/coordination/admin.rs` - Add coordination function
- `oauth2_passkey_axum/src/admin/optional.rs` - Add API endpoints
- `oauth2_passkey_axum/static/admin_user.js` - Add session status fetch
- `oauth2_passkey_axum/templates/admin_index.j2` - Add Active column
- `oauth2_passkey_axum/templates/admin_user_page.j2` - Add session info + Force Logout button

## Resolution

