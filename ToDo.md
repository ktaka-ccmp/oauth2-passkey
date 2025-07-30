# oauth2-passkey

## Todo

### High Priority

- **Simplify OAuth2 Account Linking API**: Current implementation requires understanding CSRF tokens, page session tokens, and coordinating multiple API calls (50+ lines of code). Need simpler, more intuitive API. See detailed analysis and proposed solutions in `docs/oauth2-account-linking-api-simplification.md`.
- **Finalize Public API**: Review and document all public interfaces for 1.0 release

### Medium Priority

- **Security-Focused Integration Tests**: Enhance integration test suite with comprehensive security failure scenarios to verify security controls are properly enforced
  - **OAuth2 Security Tests**:
    - Invalid/tampered state parameter rejection
    - CSRF token mismatch handling 
    - Nonce verification failures in ID tokens
    - Invalid authorization code handling
    - PKCE code challenge verification failures
    - Redirect URI validation failures
    - Origin header validation in form_post mode
  - **Passkey Security Tests**:
    - Invalid WebAuthn credential response rejection
    - Challenge tampering detection
    - Origin mismatch in WebAuthn assertions
    - Expired challenge handling
    - Invalid authenticator data validation
  - **Session Security Tests**:
    - Expired session rejection across all endpoints
    - Session boundary violations (cross-user operations)
    - Context token validation failures
    - Unauthorized admin operation attempts
  - **Cross-Flow Security Tests**:
    - Account linking without proper authentication
    - Credential addition with invalid session context
    - CSRF protection across different authentication methods
  - **Benefits**: Validates that security controls work as designed, prevents regression of security features, demonstrates robust security posture for production use
- **Expand OAuth2 Provider Support**: Add GitHub, Apple, Microsoft providers
- **Add Database Support**: MySQL/MariaDB support for more deployment options
- **Improve Demo Applications**: Custom login UI and user attribute extension examples

### New Feature Enhancements

#### Authentication Method Tracking ✅ **Recommended - Low Risk**
**Goal**: Record how a user authenticated (OAuth2 vs Passkey) in session storage
- **Implementation**:
  - Add `auth_method: AuthenticationMethod` enum to `StoredSession` struct
  - Update session creation in oauth2.rs and passkey.rs coordination modules
  - Handle backwards compatibility during deserialization
- **Benefits**:
  - Conditional UI/UX based on auth method
  - Security audit trails and logging
  - Support for different user flows per auth method
- **Complexity**: Low-Medium
- **Security Impact**: Minimal

#### OAuth2 Token Storage ⚠️ **High Value, High Security Risk**
**Goal**: Store OAuth2 tokens (access, refresh, ID) with metadata for later API calls
- **Current Gap**: Tokens are discarded after authentication - backend can't make Google API calls later
- **Implementation Requirements**:
  ```sql
  -- New table needed
  CREATE TABLE oauth2_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      provider TEXT NOT NULL,
      access_token TEXT NOT NULL,        -- Must be encrypted
      refresh_token TEXT,                -- Must be encrypted
      id_token TEXT,
      token_type TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      scope TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
  );
  ```
- **Critical Security Measures Required**:
  - **Field-level encryption** for all tokens at rest
  - **Secure key management** with proper rotation
  - **Automatic token refresh** background jobs
  - **Comprehensive audit logging** of all token access
  - **Secure token deletion** on user request
  - **Minimal scope principle** - only store tokens with required permissions
- **Alternative Approaches** (Lower Risk):
  - Session-scoped tokens (discard on logout)
  - On-demand re-authentication when API access needed
  - API proxy pattern (backend makes calls without storing user tokens)
- **Complexity**: Medium-High
- **Security Impact**: High - stored tokens = access to user's external accounts

### UI Improvements

#### Critical (Affecting User Trust & Accessibility)
- **Replace alert() dialogs** with proper toast/snackbar notification system
- **Add accessibility features**: ARIA labels, keyboard navigation, focus management
- **Implement proper error states** with inline form validation instead of just alerts
- **Add loading indicators** (spinners/progress bars) for all async operations

#### High Priority (Modern UX Standards)
- **Improve responsive design**: Add tablet breakpoints, fix mobile modal handling
- **Create confirmation dialogs** for destructive actions (replace browser confirm())
- **Fix duplicate CSS files**: Consolidate admin_user.css and summary.css
- **Add dark mode support** (already mentioned in TODOs)

#### Medium Priority (Polish & Consistency)
- **Design system**: Define consistent spacing, colors, typography, button styles
- **Smooth transitions**: Add CSS transitions for modals, state changes
- **Better mobile experience**: Larger tap targets, optimized forms
- **User-friendly error messages**: Replace technical errors with helpful guidance

#### Implementation Approach
**Keep it simple and dependency-free:**
- **No heavy JS frameworks** (React/Vue/Svelte/HTMX) - they complicate the library and force build tools on users
- **Use modern CSS** for most improvements:
  - CSS custom properties for theming (easy dark mode support)
  - CSS Grid/Flexbox for responsive layouts
  - CSS animations for smooth transitions
  - Consider lightweight classless CSS like Pico.css or Water.css (~10KB)
- **Minimal JS enhancements**:
  - Alpine.js (15KB) for declarative interactivity if needed
  - Tiny toast library like Notyf (4KB) for notifications
  - Keep vanilla JS for critical auth flows
- **Example approach**:
  ```css
  /* Modern CSS variables for theming */
  :root {
    --primary: #4285f4;
    --radius: 8px;
    --shadow: 0 2px 8px rgba(0,0,0,0.1);
  }
  [data-theme="dark"] {
    --primary: #5a9fd4;
    --bg: #1a1a1a;
  }
  ```

### Existing Items

- Use #[tracing::instrument]
  - async-backtrace
  - tokio-console https://zenn.dev/tfutada/articles/4dbb9659bb8102
- Replace "if let", "unwrap_or_else", "ok_or_else" etc. with "match", where appropriate.

- Make demo-oauth2 and demo-passkey pages to implement login page and account summary page without relying on oauth2_passkey_axum's summary and login pages.
- Another demo would be the one that extend attributes of users.

- Syncing of credentials using signalAllAcceptedCredentials?

- MySQL, MariaDB support
- Add Support for other OAuth2 providers like Apple and GitHub etc.

- Rate limiting?
- Integration test
- E2E test

## ChatGPT's assessment

After reviewing the changes more carefully, I've identified a few areas that could be improved:

Error Handling:
- In some admin functions, there are .unwrap() calls in admin_summary.js that could lead to runtime errors if data is missing.
- The get_authenticator_info(&aaguid).await.unwrap_or_default() in optional.rs could be handled with better error logging.

Code Organization:
- The relationship between default.rs and optional.rs modules could be clarified with better comments.

Modularity:
- The admin functionality is tightly coupled with the axum implementation, which might make it harder to use with other web frameworks.
- The UUID generation in gen_new_user_id switched from a custom function to the standard UUID library, which is good, but the commented-out code could be removed.

Documentation:
- Some of the new admin functions lack comprehensive documentation explaining their purpose and security implications.
- The templates could benefit from more comments explaining the data structure they expect.
- Add links to longer-form tutorials or blog posts if available.

UI/UX:

Examples:
- Add a dedicated "Examples" section to the README with full, runnable code for common patterns (e.g., login, logout, admin-only routes).

Feature Flags:
- Add a table to the README summarizing all feature flags (name, default, description) for quick reference.

Troubleshooting/FAQ:
- Consider adding a short FAQ or troubleshooting section to the README to address common integration pitfalls and frequently asked questions.

Badges & Metadata:
- If CI, test, or coverage badges are added, group them at the top of the README for better project status visibility.
- The admin UI lacks proper responsive design for smaller screens in some areas.
- Error messages could be more user-friendly and provide clearer guidance on how to resolve issues.

These improvements would enhance the maintainability, security, and user experience of the admin functionality while keeping the code minimal and focused on the core requirements.

## Half Done

- [Need to investigate] I'm wondering if we should stop creating new user_handle everytime we create a new passkey credential.Instead we might have to use the existing user_handle for a logged in user. This will align well with syncing of credentials using the signalAllAcceptedCredentials.
  - We can now control this by setting PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL environment variable.
  - By having user_handle unique for user i.e. not for every credential, we seem to be able to only register one passkey credential per user in Google Password Manager.

- signalUnknownCredential seems not working on Android device.
  - Seems like it hasn't been supported yet.

- Once we have AAGUID, we should fix the logic for deleting credentials in register.rs to use a combination of "AAGUID" and user_handle.
- Important todo: we delete credentials for a combination of "AAGUID" and user_handle
  - But we can't distinguish multiple authenticators of the same type,
  - e.g. Google Password Managers for different accounts or two Yubikeys with the same model

  - FIDO U2F attestation is implemented experimentally. It requires to send non-empty allowedCredentials parameter i.e. first decide which user to authenticate. It may also require the following settings:
    - PASSKEY_USER_VERIFICATION='preferred'
    - PASSKEY_AUTHENTICATOR_ATTACHMENT='cross-platform'
    - PASSKEY_REQUIRE_RESIDENT_KEY=false
    - PASSKEY_RESIDENT_KEY='preferred'

## Done

- Passkey sync between RP and Authenticator using signalAllAcceptedCredentials.
- Enable modification of User.account and User.label for logged in user.
- Enable deletion of logged in user then logout.
- Enable deletion of Passkey credential for logged in user.
- Enable unlinking of OAuth2 account for logged in user.
- Examine if we should use OAuth2Coordinator and PasskeyCoordinator.
- Autofill user.name as default values for Passkey register dialog's name and display name.
- Related Origin Requests
(https://passkeys.dev/docs/advanced/related-origins/)
- Use parseCreationOptionsFromJSON and parseAuthenticationOptionsFromJSON to simplify passkey.js implementation. Won't do as this requires webauthn-json dependency.
- Deal with halfway registration and authentication in passkey.js.

- Standardize binary data encoding throughout the backend codebase:
  - Use Base64 URL_SAFE_NO_PAD consistently for all credential IDs and public keys
  - Update database schema and existing records if necessary

- Make user id and OAuth2 account id collision-less.
- ~~[Need to investigate]~~(It's working now) Passkey sync between RP and Authenticator using signalUnknownCredential not working.

- ✔️ Session boundary protection for authentication flows. When a user adds a new passkey credential or links a new OAuth2 account, we ensure session consistency:
  - Implemented dedicated functions with clear intent separation through explicit modes:
    - `add_to_existing_user` mode - For adding credentials to existing users
    - Default mode - For creating new users with credentials when no user is logged in
  - For OAuth2 account linking:
    - Context token verification before redirecting to OAuth2 provider
    - State parameter used to maintain user context across the redirect
    - Session renewal after successful authentication
    - See detailed analysis in [docs/oauth2-user-verification.md](docs/oauth2-user-verification.md)
  - For Passkey credential addition:
    - Context token verification before initiating registration
    - Session verification during the registration process
- Prefix of tables in database can be configured in .env file.

- Consolidate liboauth2, libpasskey, libsession and libstorage into libauth.

- Want to change the directory structure of the endpoints for Passkey and OAuth2
  - Currently Passkey endpoints should be mounted at OAUTH2_ROUTE_PREFIX(default: /passkey)
  - OAuth2 endpoints should be mounted at OAUTH2_ROUTE_PREFIX(default: /oauth2)
  - OAUTH2_ROUTE_PREFIX and PASSKEY_ROUTE_PREFIX are referenced by handlers and the endpoints are reflected in the templates and javascript files.
  - I want to change it to O2P_ROUTE_PREFIX/passkey and O2P_ROUTE_PREFIX/oauth2 respectively. By doing so we only need to nest single tree in the application. The summary endpoint can be also nested in the same tree freeing from necessity of explicitly mounting it in the application.

- Middleware based page protection i.e. create a likes of is_authorized middleware.
- Fix: add O2P_ROUTE_PREFIX to "fetch('/summary/user-info', {"
- Currently if a user is showing two pages, the one for index page for unauthenticated user and the one for summary page for authenticated user, then tries to create a new user with a new passkey in the first page, the passkey will be registered for the authenticated user in the second page.
  - Fixed by checking if the user isn't authenticated
```rust
						match auth_user {
								Some(_) => return Err(CoordinationError::UnexpectedlyAuthorized.log()),
								None => {}
						};
```
- When using Delete User button, deletion of passkey credentials aren't notified to Passkey Authenticator.
- Change name: libaxum to oauth2_passkey_axum
- Schema check when initializing database connection. Make sure the schema the program is expecting is the same as the one in the database.
- Enable update of name and displayname feild for passkey credentials. Also notify the update to autheticator using signalCurrentUserDetails.

- Cleanup frontend
- Adjust visibility of functions, structs, enums, etc. What needs to be public?
- idtoken.rs: make it use CacheStore instead of current mechanisms.
- Utilize feature gate to enable/disable supplementary frontend templates and JavaScript.
- Completely separate create_account function from add_to_user function to avoid the case where new user is created even though user is already logged in.
- Debug: there are cases signalCurrentUserDetails doesn't work properly.

- Add additional attributes to PasskeyCredentials.
  - For example, authenticator_name, like Google Password Manager, App Password Manager, YubiKey etc.
  - It is also possible that a user has multiple Google Password Managers with different Google accounts, so is possible for Apple Password Managers.
  - A user may also have multiple YubiKeys.
- Add AAGUID to PasskeyCredentials.
  - or information about the authenticator retrieved using AAGUID
  - need to figure out how to get an authenticator icon using AAGUID
  - https://web.dev/articles/webauthn-aaguid
  - https://fidoalliance.org/metadata/
  - https://github.com/passkeydeveloper/passkey-authenticator-aaguids
  - https://passkeydeveloper.github.io/passkey-authenticator-aaguids/explorer/
  - https://www.corbado.com/glossary/aaguid


Security Considerations:
- The admin authentication relies solely on the is_admin flag without additional safeguards like CSRF protection for critical operations.
  - Admin authentication now appears to be protected not only by the is_admin flag but also by requiring a valid context token for critical operations, addressing the previous security concern.
- The page context validation is good, but could benefit from a more robust token-based approach.
  - Page context validation uses a robust, token-based approach with CSRF and context tokens, providing strong protection against CSRF and session boundary issues.

Performance:
- In user_summary function, there's a potential N+1 query issue when fetching authenticator info for each credential.
  - The N+1 query issue in user_summary has been fixed by batching authenticator info retrieval.
- The format_date_tz function could be optimized to avoid parsing the timezone for each date formatting operation.
  - The format_date_tz function now uses a cached timezone map, avoiding repeated parsing.

- The feature flags (admin-pages and optional-pages) are introduced but their purpose isn't well-documented in the code.

- Create a page to list all users which will be accessible only by admin.
  - The page will have button that will delete the user.
  - The page will have button that will toggle the admin flag.
  - The page will have button or link to the summary page of the user.
  - In the summary page, the admin can unlink OAuth2 accounts and delete passkey credentials.
  - I am wondering if we should utilize existing handler for summary page for a login user and helper functions or create a new handler and set of helper functions dedicated for admin. My worries is that we can reduce the code by utilizing existing handlers but we have functions with mixed concerns, thus resulting in higher chances of creating security bugs

- Does page context token verification work as csrf protection?
  - Suppose the situation where a malicious user tries to let the admin give him admin privileges, or modify arbitrary user's account details.

- Implement Admin Account idea
  - ~~Modify the User table to add admin flag and sequence number.~~
  - ~~The first user i.e. sequence number 1 will be the admin.~~
  - He has the power to modify all attributes of all users.
  - Can list and manage all users.

- Modify is_authenticated middleware so that it can embed csrf_token in the extention field.
- csrf_token is also automatically delivered to the client as an X-CSRF-Token response header.
- Re-examine the role of page context token.
- Re-examine the current implementation of CSRF protection in OAuth2 flow.
- Modify demo pages to include link to available pages.

- **[FIXED] Session Expiration Handling Inconsistency**
  - ✅ Fixed: Added expiration check and automatic deletion logic to `get_csrf_token_from_session()` and `get_user_and_csrf_token_from_session()`
  - ✅ Both functions now consistently check `stored_session.expires_at < Utc::now()` and delete expired sessions
  - ✅ Both functions return `SessionError::SessionExpiredError` for expired sessions, matching `is_authenticated()` behavior
  - ✅ Updated test `test_get_user_and_csrf_token_from_session_expired_session` to verify expired sessions are properly deleted
  - ✅ All session-related tests now pass (406 total tests passing)
  - **Location**: `oauth2_passkey/src/session/main/session.rs`
  - **Previously**: Memory leaks in cache store, inconsistent session validation behavior

- add at_hash verification for oidc access token

- ~~**Fix CI/CD**: Update `.github/workflows/ci.yml` branch references (master → main or actual branch names)~~ ✅ **DONE** - CI is already properly configured for master/develop branches with comprehensive testing, security audits, and documentation checks
- ~~**Add Tracing**: Implement structured logging with `tracing` crate for production observability~~ ✅ **DONE** - Comprehensive tracing implementation completed
  - ✅ Enhanced error context using standard tracing (tracing-error not needed)
  - ✅ Documented how to add HTTP tracing middleware (user's choice)
  - ✅ Instrumented all coordination layer functions (OAuth2 & Passkey)
  - ✅ Added session management tracing with performance timing
  - ✅ Enhanced error logging with structured context and span correlation
  - ✅ Storage operations instrumented with database query timing
  - ✅ Created detailed implementation guide in docs/implementing-tracing.md
- ~~**Clean Error Handling**: Replace 30+ `.unwrap()` calls in session module with proper error handling~~ ✅ **DONE** - Session module already uses proper error handling in production code; `.unwrap()` calls are appropriately isolated to test code only

- ~~**Integration Tests**: Add end-to-end tests for complete authentication flows~~ ✅ **DONE** - Comprehensive integration test suite implemented with 29 tests covering all authentication flows
  - ✅ Production-grade Axum mock OIDC provider with complete OAuth2/OIDC specification compliance
  - ✅ Full OAuth2 flows (new user registration, existing user login, account linking, error scenarios)
  - ✅ Complete Passkey flows (registration, authentication, credential addition, error handling)
  - ✅ Cross-method authentication (OAuth2 + Passkey combinations)
  - ✅ API client flows with proper CSRF token handling
  - ✅ Enhanced test reliability with exponential backoff port conflict handling
  - ✅ Test infrastructure optimization (~400 lines of unused code removed)
  - ✅ Perfect test isolation using unique table prefixes and serial execution
  - ✅ Fast execution (~4 seconds for entire integration suite)
- ~~**Implement OIDC Discovery**: Replace hardcoded JWKS URL with dynamic discovery from `/.well-known/openid-configuration`~~ ✅ **DONE** - Complete OIDC Discovery implementation
  - ✅ OAUTH2_ISSUER_URL now required environment variable for automatic endpoint discovery
  - ✅ All OAuth2 endpoints (auth, token, userinfo, JWKS) discovered dynamically via `.well-known/openid-configuration`
  - ✅ Environment variable overrides still supported for specific endpoint customization
  - ✅ Full production testing with persistent Axum mock server providing OIDC Discovery endpoint
  - ✅ All integration tests validate OIDC Discovery functionality and nonce verification compliance

## Memo

```text
Can you take a look the following diff carefully and suggest improvements. If it doesn't introduce any bugs and every change is OK suggest a commit message plz.

Make sure that we are not modifying any existing functionality except for just adding inline unit tests.
```
