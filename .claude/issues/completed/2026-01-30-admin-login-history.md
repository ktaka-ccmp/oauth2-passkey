# Issue: Login History View (Admin + User)

## ID: 2026-01-30-03

## Status: completed

## Priority: medium

## Difficulty: large

## Description

Add login history viewing capability:
1. **Admin**: View any user's login history from admin panel (audit trail for security monitoring)
2. **User**: View own login history from account page (security awareness, detect unauthorized access)

## Related Files

- `oauth2_passkey/src/login_history/` - New module for login history storage
- `oauth2_passkey/src/coordination/login_history.rs` - Coordination layer functions
- `oauth2_passkey/src/coordination/passkey.rs` - Record login on authentication
- `oauth2_passkey/src/coordination/oauth2.rs` - Record login on OAuth2 callback
- `oauth2_passkey_axum/src/login_history.rs` - Axum handlers
- `oauth2_passkey_axum/src/admin/mod.rs` - Admin router integration
- `oauth2_passkey_axum/templates/admin_user_page.j2` - Admin user detail page
- `oauth2_passkey_axum/src/user/mod.rs` - User router integration
- `oauth2_passkey_axum/templates/user_account.j2` - User account page

## Notes

**Data Recorded**:
- User ID
- Login timestamp
- Authentication method (passkey/oauth2)
- IP address (masked for user view, full for admin)
- User-Agent
- Success/failure status
- Credential ID (for passkey logins)
- Provider and Provider User ID (for OAuth2 logins)
- Failure reason (if applicable)

**Implementation Summary**:

1. **Database Schema**: Created `o2p_login_history` table with indexes
   - Supports both SQLite and PostgreSQL
   - Auto-initialized on startup

2. **Storage Layer**: New `oauth2_passkey/src/login_history/` module
   - `LoginHistoryStore` with `init()`, `insert()`, `get_by_user()` methods
   - Parallel SQLite and PostgreSQL implementations

3. **Coordination Layer**: New `oauth2_passkey/src/coordination/login_history.rs`
   - `record_login_success()` - Called after successful authentication
   - `get_own_login_history()` - For user's own view (masked IP)
   - `get_user_login_history_admin()` - For admin view (full details)

4. **Axum Integration**: New `oauth2_passkey_axum/src/login_history.rs`
   - `extract_login_context()` - Extract IP and User-Agent from headers
   - User endpoint: `GET /o2p/user/login_history`
   - Admin endpoint: `GET /o2p/admin/user/{user_id}/login_history`

5. **UI Integration**:
   - User account page: "Recent Login History" section with auto-load
   - Admin user page: "Login History" section with refresh button

**Privacy Features**:
- IP masking for user view (last octet hidden for IPv4, last segment for IPv6)
- User-Agent truncation (512 chars max)
- Query params: `limit` (default 50 for admin, 10 for user), `offset`

## Resolution

Completed 2026-02-07. Full implementation across all four phases:
- Phase 1: Storage layer with SQLite/PostgreSQL support
- Phase 2: Coordination layer with masked/unmasked history retrieval
- Phase 3: Axum handlers with login context extraction
- Phase 4: UI components for both user and admin pages

All tests pass. Login history is recorded for both passkey and OAuth2 authentication methods.
