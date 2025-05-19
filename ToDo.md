# oauth2-passkey

## Todo

- Tests
- GitHub Actions
- Decide on Public API
- Tracing
  - Use tracing-error crate https://crates.io/crates/tracing-error
  - Use https://docs.rs/tower-http/latest/tower_http/trace/index.html
  - https://docs.rs/tracing/latest/tracing/
- Use #[tracing::instrument]
  - async-backtrace
  - tokio-console https://zenn.dev/tfutada/articles/4dbb9659bb8102
- Replace "if let", "unwrap_or_else", "ok_or_else" etc. with "match", where appropriate.

- Modify demo pages to include link to available pages.
- Make demo-oauth2 and demo-passkey pages to implement login page and account summary page without relying on oauth2_passkey_axum's summary and login pages.

- Syncing of credentials using signalAllAcceptedCredentials?

- Re-examine the current implementation of CSRF protection in OAuth2 flow.

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

UI/UX:
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

## Memo

```text
Can you take a look the following diff carefully and if we aren't introducing any bugs and every change is OK suggest a commit message plz.
```
