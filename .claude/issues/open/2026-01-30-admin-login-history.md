# Issue: Login History View (Admin + User)

## ID: 2026-01-30-03

## Status: open

## Priority: medium

## Difficulty: large

## Description

Add login history viewing capability:
1. **Admin**: View any user's login history from admin panel (audit trail for security monitoring)
2. **User**: View own login history from account page (security awareness, detect unauthorized access)

## Related Files

- `oauth2_passkey/src/storage/` - Database layer for new table
- `oauth2_passkey/src/coordination/passkey.rs` - Record login on authentication
- `oauth2_passkey/src/coordination/oauth2.rs` - Record login on OAuth2 callback
- `oauth2_passkey_axum/src/admin/` - Admin handlers
- `oauth2_passkey_axum/templates/admin_user_page.j2` - Admin user detail page
- `oauth2_passkey_axum/src/user/` - User handlers
- `oauth2_passkey_axum/templates/user_account.j2` - User account page

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

4. **Admin UI**: Add history section to admin user detail page
   - Table showing recent logins
   - Filter by date range
   - Pagination for large histories

5. **User UI**: Add history section to user account page (`/o2p/user/account`)
   - Show user's own login history
   - Recent logins (last 10-20 entries)
   - Alert if suspicious activity (new IP, new device)

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

