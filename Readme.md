# oauth2-passkey

## Todo

- Tests
- GitHub Actions
- Decide on Public API
- Tracing
	- Use tracing-error crate https://crates.io/crates/tracing-error
	- Use https://docs.rs/tower-http/latest/tower_http/trace/index.html
	- https://docs.rs/tracing/latest/tracing/
- Completely separate create_account function from add_to_existing_user function to avoid the case where new user is created even though user is already logged in.
- Replace "if let", "unwrap_or_else", "ok_or_else" etc. with "match", where appropriate.
- Implement Admin Account
	- Password login for the first time, disable it for next time.
	- Mandate passkey registration during first session.
	- Can list and manage all users.
- Debug: there are cases signalCurrentUserDetails doesn't work properly.

## Half Done

- [Need to investigate] I'm wondering if we should stop creating new user_handle everytime we create a new passkey credential.Instead we might have to use the existing user_handle for a logged in user. This will align well with syncing of credentials using the signalAllAcceptedCredentials.
	- We can now control this by setting PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL environment variable.
	- By having user_handle unique for user i.e. not for every credential, we seem to be able to only register one passkey credential per user in Google Password Manager.

- signalUnknownCredential seems not working on Android device.
	- Seems like it hasn't been supported yet.

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

## Memo

```text
Can you take a look the following diff carefully and if we aren't introducing any bugs and every change is OK suggest a commit message plz.
```
