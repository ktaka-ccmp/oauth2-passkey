# Issue: Audit Page Enhancement - Date Filtering and Security Event Logging

## ID: 2026-02-08-01

## Status: completed

## Priority: medium

## Difficulty: large

## Description

Enhance the login history feature with dedicated pages and improved filtering capabilities
for both users and administrators. Also add OAuth2 CSRF attack detection logging.

### User Side Improvements
1. **User Detail Page**: Limit login history display to latest 5 entries
2. **Dedicated History Page**: Create `/o2p/user/login_history_page` with:
   - Date range filtering (from/to)
   - Pagination

### Admin Side Improvements
1. **Admin Audit Page**: Create `/o2p/admin/audit_page` with:
   - Date range filtering (from/to)
   - User filtering (by user_id)
   - Success/Failure filter (for attack detection)
   - Pagination

### Security Event Logging
1. **OAuth2 CSRF Detection**: Log anonymous security events when OAuth2 state validation fails
   - Record IP address and User-Agent (no user_id since user is unknown)
   - Enables detection of CSRF attack patterns from same IP

## Technical Design

### Anonymous Security Events
Used existing `o2p_login_history` table with empty user_id for anonymous events.

### API Endpoints
- `GET /o2p/user/login_history_page` - User's own history page (HTML)
- `GET /o2p/user/login_history?from=&to=&limit=&offset=` - API with date filter
- `GET /o2p/admin/audit_page` - Admin audit page (HTML)
- `GET /o2p/admin/audit?from=&to=&user_id=&success=&limit=&offset=` - API

## Related Files

- `oauth2_passkey/src/audit/storage/sqlite.rs`
- `oauth2_passkey/src/audit/storage/postgres.rs`
- `oauth2_passkey/src/audit/storage/store_type.rs`
- `oauth2_passkey/src/audit/types.rs`
- `oauth2_passkey/src/coordination/login_history.rs`
- `oauth2_passkey/src/coordination/oauth2.rs`
- `oauth2_passkey_axum/src/login_history.rs`
- `oauth2_passkey_axum/templates/user_account.j2`
- `oauth2_passkey_axum/templates/user_login_history.j2` (new)
- `oauth2_passkey_axum/templates/admin_audit.j2` (new)

## Notes

- Follows existing pattern for admin/user pages
- OAuth2 CSRF logging uses existing LoginHistoryEntry with empty user_id
- Date filtering uses chrono::DateTime for consistency
- Passkey failure logging also implemented to track failed authentication attempts

## Resolution

Implemented all features:

1. **Storage Layer**:
   - Added `get_login_history_by_user_with_date_range_sqlite/postgres` for date filtering
   - Added `query_login_history_admin_sqlite/postgres` for admin audit queries

2. **Coordination Layer**:
   - Added `get_own_login_history_with_date_range` for user date filtering
   - Added `query_login_history_admin` for admin audit queries
   - Added `record_anonymous_security_event` for OAuth2 CSRF failures

3. **Axum Layer**:
   - Added `LoginHistoryQuery` and `AdminAuditQuery` structs
   - Updated `get_my_login_history` with date filter support
   - Added `login_history_page` handler
   - Added `get_admin_audit` and `admin_audit_page` handlers

4. **Templates**:
   - Created `user_login_history.j2` with date picker and pagination
   - Created `admin_audit.j2` with user ID, date, and success/failure filters
   - Updated `user_account.j2` to show 5 entries with "View All" link

5. **Security**:
   - OAuth2 CSRF failures now logged via `record_anonymous_security_event`
   - Passkey authentication failures logged with credential_id for user tracking
