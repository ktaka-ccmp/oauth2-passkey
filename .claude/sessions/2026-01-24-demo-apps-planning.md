# Session Snapshot: Demo Apps Planning

**Date**: 2026-01-24
**Topic**: Planning demo-profile and demo-todo applications

## Current Task

Planning and preparing to implement two new demo applications that demonstrate how to extend user data with application-specific tables:

1. **demo-profile**: User profile extension with avatar support
2. **demo-todo**: User-specific data management (ToDo list)

## Completed Work

### Documentation Improvements (committed: d772dde)
- Restructured `csrf-handling.md` with unified terminology
- Made Middleware Comparison a subsection in `route-protection.md`
- Added numbered references to `framework.md`
- Simplified other demos into table in `quick-start.md`
- Added O2P_LOGIN_URL note to `custom-pages.md`
- Added demo-custom-login to `architecture.md`
- Reorganized SUMMARY.md into 7 parts

### server-setup.md Improvements (uncommitted)
- Added "Default Log Levels" table explaining debug vs release build logging
- Updated Self-Signed Certificate Setup to reference gen_certs.sh script
- Added cloudflared tunnel example

### gen_certs.sh Distribution (uncommitted)
- Copied gen_certs.sh to demo-both and demo-custom-login
- All demos now have the certificate generation script

## Key Decisions

1. **User attribute extension pattern**: Use separate tables linked by `user_id` rather than modifying the library's user table

2. **Avatar support in demo-profile**:
   - Library already captures Google `picture` URL in `oauth2_accounts` table
   - `list_accounts_core()` and `OAuth2Account` are re-exported from `oauth2_passkey_axum`
   - Demo can fetch Google avatar via `OAuth2Account.picture` field

3. **Demo application selection**:
   - demo-profile: Profile extension with avatar, bio, theme
   - demo-todo: CRUD operations for user-specific data

## Files Modified (Uncommitted)

- `docs/src/integration/server-setup.md` - logging table, gen_certs.sh reference, tunnel example
- `demo-both/self_signed_certs/gen_certs.sh` - copied from demo-passkey
- `demo-custom-login/self_signed_certs/gen_certs.sh` - copied from demo-passkey

## Next Steps

1. **Commit pending changes**: server-setup.md and gen_certs.sh additions

2. **Implement demo-profile**:
   ```
   demo-profile/
   ├── Cargo.toml
   ├── .env.example
   ├── src/
   │   ├── main.rs          # Server startup, routing
   │   ├── db.rs            # PostgreSQL, user_profiles table
   │   └── handlers.rs      # HTTP handlers
   ├── templates/
   │   ├── index.j2
   │   └── profile.j2
   └── self_signed_certs/
       └── gen_certs.sh
   ```

   Database schema:
   ```sql
   CREATE TABLE user_profiles (
       user_id TEXT PRIMARY KEY,
       display_name TEXT,
       bio TEXT,
       avatar_url TEXT,        -- From Google OAuth2 picture
       theme TEXT DEFAULT 'light',
       created_at TIMESTAMPTZ DEFAULT NOW(),
       updated_at TIMESTAMPTZ DEFAULT NOW()
   );
   ```

3. **Implement demo-todo** (after demo-profile)

## Important Context

### Accessing Google Avatar
```rust
use oauth2_passkey_axum::{list_accounts_core, OAuth2Account, UserId};

// Get OAuth2 accounts for user
let user_id = UserId::new(user_id_string)?;
let accounts = list_accounts_core(user_id).await?;

// Find Google account and get picture URL
let google_picture = accounts.iter()
    .find(|a| a.provider == "google")
    .and_then(|a| a.picture.clone());
```

### OAuth2Account Structure (relevant fields)
- `picture: Option<String>` - URL to user's profile picture from OAuth2 provider
- `provider: String` - e.g., "google"
- `user_id: String` - Links to library's user table

## Related Files

- [oauth2_passkey_axum/src/lib.rs](oauth2_passkey_axum/src/lib.rs#L93-L95) - Re-exports for custom summary pages
- [oauth2_passkey/src/oauth2/types.rs](oauth2_passkey/src/oauth2/types.rs#L32) - OAuth2Account.picture field
