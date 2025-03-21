# axum-oauth2-passkey

## Todo

- Middleware based page protection i.e. create a likes of is_authorized middleware.
- We'll do this after the tests are implemented
- Schema check when initializing database connection. Make sure the schema the program is expecting is the same as the one in the database.
- When using Delete User button, deletion of passkey credentials aren't notified to Passkey Authenticator.
- Adjust visibility of functions, structs, enums, etc. What needs to be public?
- signalCurrentUserDetails seems not working on Android device.

## Half Done

- [Need to investigate] I'm wondering if we should stop creating new user_handle everytime we create a new passkey credential.Instead we might have to use the existing user_handle for a logged in user. This will align well with syncing of credentials using the signalAllAcceptedCredentials.
  - We can now control this by setting PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL environment variable.
  - By having user_handle unique for user i.e. not for every credential, we seem to be able to only register one passkey credential per user in Google Password Manager.

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
- ~~[Need to investigate]~~(It's working now) Passkey sync between RP and Authenticator using signalCurrentUserDetails not working.

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

## Memo

```text
Can you take a look the following diff and if we aren't introducing any bugs and every change is OK suggest a commit message plz.
```
