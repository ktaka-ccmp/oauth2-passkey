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

## Resolution

