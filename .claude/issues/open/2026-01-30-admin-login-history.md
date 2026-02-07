# Issue: Admin Login History View

## ID: 2026-01-30-03

## Status: open

## Priority: medium

## Description

Add ability for administrators to view user login history from the admin panel. This provides audit trail visibility for security monitoring and troubleshooting.

## Related Files

- `oauth2_passkey/src/storage/` - Database layer for new table
- `oauth2_passkey/src/coordination/passkey.rs` - Record login on authentication
- `oauth2_passkey/src/coordination/oauth2.rs` - Record login on OAuth2 callback
- `oauth2_passkey_axum/src/admin/` - Admin handlers
- `oauth2_passkey_axum/templates/admin_user.j2` - Admin user detail page

## Notes

**Data to Record**:
- User ID
- Login timestamp
- Authentication method (passkey/oauth2)
- IP address
- User-Agent
- Success/failure status
- Credential ID (for passkey logins)

**Implementation Approach**:

1. **Database Schema**: Create `login_history` table
   ```sql
   CREATE TABLE login_history (
       id SERIAL PRIMARY KEY,
       user_id TEXT NOT NULL,
       login_at TIMESTAMP NOT NULL DEFAULT NOW(),
       auth_method TEXT NOT NULL,  -- 'passkey' or 'oauth2'
       ip_address TEXT,
       user_agent TEXT,
       success BOOLEAN NOT NULL,
       credential_id TEXT,  -- for passkey logins
       FOREIGN KEY (user_id) REFERENCES users(user_id)
   );
   ```

2. **Storage Layer**: Add functions in `oauth2_passkey/src/storage/`
   - `record_login()` - Insert login record
   - `get_login_history(user_id, limit)` - Retrieve history

3. **Coordination Layer**: Call `record_login()` after authentication
   - In `handle_finish_authentication_core()` for passkey
   - In OAuth2 callback handler for Google login

4. **Admin UI**: Add history section to user detail page
   - Table showing recent logins
   - Filter by date range
   - Pagination for large histories

**Dependencies**:
- Need to extract IP address and User-Agent from request headers
- May need to pass additional context through coordination layer

**Privacy Considerations**:
- IP addresses are PII - consider retention policy
- May want configurable history retention period
- GDPR compliance: user should be able to see their own history

**Related Issues**:
- `2026-01-30-02`: Admin Force Logout (complementary feature)

## Resolution

