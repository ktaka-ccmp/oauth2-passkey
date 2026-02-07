# Issue: Admin Force Logout Feature

## ID: 2026-01-30-02

## Status: completed

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

---

## 2026-02-07 Update 2: Clickable Indicator for Quick Force Logout

### Enhancement
Make the session status indicator (●) in admin index clickable to allow direct force logout without navigating to user detail page.

### Implementation
1. Change indicator from `<span>` to clickable `<button>`
2. Only active indicators (●) are clickable
3. Click shows confirm dialog: "Force logout {username}?"
4. On confirm, call existing `POST /o2p/admin/user/{user_id}/logout`
5. On success, refresh indicator (● → ○)

### UX Considerations
- Hover effect to indicate clickability (cursor: pointer, slight color change)
- Inactive indicators (○) remain non-clickable
- Clear visual feedback after successful logout

## Resolution

### Completed 2026-02-07

All phases of the Admin Force Logout feature have been implemented:

**Core API & Coordination Layer:**
- `get_active_session_count(session_id, user_id)` - Get session count for a specific user
- `get_all_active_sessions(session_id)` - Get session counts for all users (bulk API)
- `force_logout_user(session_id, target_user_id)` - Terminate all sessions for a user

**Admin Endpoints (Axum):**
- `GET /o2p/admin/sessions` - Returns JSON `{ user_id: session_count, ... }`
- `POST /o2p/admin/user/{user_id}/logout` - Force logout with JSON response

**Admin Index (User List) Enhancements:**
- Added "Active" column with session status indicator
- Green dot (●) for active sessions, gray circle (○) for inactive
- **Clickable indicator**: Active indicators can be clicked to force logout directly
- Current admin user's indicator is non-clickable (prevents self-logout)
- Hover effect on clickable indicators (scale + brightness)
- Confirmation dialog before force logout
- 5-second polling for real-time session status updates

**Admin User Detail Page Enhancements:**
- "Active Sessions: N" display in user info section
- "Force Logout" button (visible when sessions > 0)
- Real-time session count updates

**Security:**
- All endpoints require admin privileges (verified at both handler and coordination layer)
- CSRF token validation on POST requests
- Defense in depth: admin check at Axum handler layer AND coordination layer

**Unit Tests Added:**
- `test_get_active_session_count_requires_admin`
- `test_get_all_active_sessions_requires_admin`
- `test_force_logout_user_requires_admin`
- `test_get_all_active_sessions_success`
- `test_force_logout_user_success`

**Bug Fix:**
- Updated `insert_test_session` in test_utils to also update user_sessions mapping

**Files Modified:**
- `oauth2_passkey/src/coordination/admin.rs` - Added coordination functions
- `oauth2_passkey/src/coordination/admin/tests.rs` - Added 5 new tests
- `oauth2_passkey/src/session/main/test_utils.rs` - Fixed user_sessions mapping
- `oauth2_passkey_axum/src/admin/optional.rs` - Added endpoints + current_user_id to template
- `oauth2_passkey_axum/templates/admin_index.j2` - Clickable indicator + polling
- `oauth2_passkey_axum/templates/admin_user_page.j2` - Session info + Force Logout button
- `oauth2_passkey_axum/static/admin_user.js` - Admin status toggle function
- `CHANGELOG.md` - Documented new feature
