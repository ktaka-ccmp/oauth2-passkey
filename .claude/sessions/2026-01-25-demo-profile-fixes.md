# Session Snapshot: demo-profile Fixes

## Current Task

Fixing issues in demo-profile application after initial creation. The demo-profile app demonstrates extending user attributes with a separate PostgreSQL table.

## Files Modified

- `demo-profile/src/main.rs` - Added display_name and bio to TemplateUser, removed redirect on logout
- `demo-profile/src/handlers.rs` - Changed save redirect from `/profile` to `/`
- `demo-profile/templates/index.j2` - Show display_name/bio, fixed logout URL

## Key Decisions

1. **Display Name vs Auth Label**: Profile's `display_name` is separate from oauth2-passkey's `user.label`
   - `user.label` - Authentication label from Google/passkey (stored in library's users table)
   - `profile.display_name` - Application-specific (stored in demo-profile's user_profiles table)

2. **Logout Route**: Correct path is `/o2p/user/logout?redirect=/` (not `/o2p/logout`)

3. **Post-Save Redirect**: After saving profile, redirect to `/` (home) so user sees their updated info

4. **Middleware Selection**:
   - `is_authenticated_redirect` provides CsrfToken/CsrfHeaderVerified as Extensions
   - `is_authenticated_user_redirect` does NOT provide CsrfToken
   - Use `AuthUser` directly as extractor (not via Extension)

## Issues Fixed This Session

1. **CsrfToken Extension Error**: Changed middleware from `is_authenticated_user_redirect` to `is_authenticated_redirect`
2. **Display Name/Bio Not Shown**: Added fields to TemplateUser and updated index.j2 template
3. **Logout Not Working**: Fixed URL from `{{ prefix }}/logout` to `{{ prefix }}/user/logout?redirect=/`
4. **Save Redirect**: Changed from `/profile` to `/` for better UX

## Next Steps

1. Test the complete profile flow:
   - Login -> Edit profile -> Save -> See changes on home page -> Logout
2. Consider creating demo-todo application for CRUD operations
3. Commit demo-profile when ready

## Context

- demo-profile uses PostgreSQL for user_profiles table (separate from oauth2-passkey storage)
- Avatar URL is fetched from Google OAuth2 account via `list_accounts_core()`
- PostgreSQL 18+ requires volume mount format: `./data:/var/lib/postgresql` (not `/var/lib/postgresql/data`)
