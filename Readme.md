# axum-oauth2-passkey

## Todo

- Middleware based page protection i.e. create a likes of is_authorized middleware.
- Consolidate liboauth2, libpasskey, libsession and libstorage into libauth.
- We'll do this after the tests are implemented
- Schema check when initializing database connection.

- [Need to investigate] Deal with session boundary problems. When a user decides to add a new passkey credential or link a new oauth2 account, we have to make sure that the session is still valid. Current implementation creates a new user if there is no session, even if the user is intending to add a new passkey credential or link a new oauth2 account to existing user.
  - Maybe we should create new dedicated functions, add_new_passkey_to_user and add_new_oauth2_account_to_user, which should never create a new user.
    - OAuth2: Verify {user.id(embedded in the page), session.user_id} match before redirecting to OAuth2 provider and upon receiving the callback, conveying the "user.id" in the state parameter. Maybe we should avoid form_post mode to have a valid session in the callback. Use the same session before and after linking.
    - Passkey: Verify {user.id(embedded in the page), session.user_id} match before start_register and finish_register.
  - We should also create a new dedicated function, add_new_user_with_passkey and add_new_user_with_oauth2_account.
    - We should make sure there isn't a session beginning and ending of the process.

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

## Memo

```text
Can you take a look the following diff and if we aren't introducing any bugs and every change is OK suggest a commit message plz.

```
