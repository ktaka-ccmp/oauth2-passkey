# axum-oauth2-passkey

## Todo

- Middleware based page protection i.e. create a likes of is_authorized middleware.
- Consolidate liboauth2, libpasskey, libsession and libstorage into libauth.
- Standardize binary data encoding throughout the backend codebase:
  - Use Base64 URL_SAFE_NO_PAD consistently for all credential IDs and public keys
  - Update database schema and existing records if necessary
  - We'll do this after the tests are implemented

- [Need to investigate] Passkey sync between RP and Authenticator using signalCurrentUserDetails not working.

## Half Done

- [Need to investigate] I'm wondering if we should stop creating new user_handle everytime we create a new passkey credential.Instead we might have to use the existing user_handle for a logged in user. This will align well with syncing of credentials using the signalAllAcceptedCredentials.
  - We can now control this by setting PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL environment variable.
  - By having user_handle unique for user i.e. not for every credential, we seem to be able to only register one passkey credential per user in Google Password Manager.

## Done

- ~~Passkey sync between RP and Authenticator using signalAllAcceptedCredentials.~~
- ~~Enable modification of User.account and User.label for logged in user.~~
- ~~Enable deletion of logged in user then logout.~~

- ~~Enable deletion of Passkey credential for logged in user.~~
- ~~Enable unlinking of OAuth2 account for logged in user.~~
- ~~Examine if we should use OAuth2Coordinator and PasskeyCoordinator.~~
- ~~Autofill user.name as default values for Passkey register dialog's name and display name.~~
- ~~Related Origin Requests
(https://passkeys.dev/docs/advanced/related-origins/)~~
- ~~Use parseCreationOptionsFromJSON and parseAuthenticationOptionsFromJSON to simplify passkey.js implementation.~~ Won't do as this requires webauthn-json dependency.
- ~~Deal with halfway registration and authentication in passkey.js.~~

## Memo

```text
Can you take a look the following diff and if we aren't introducing any bugs and every change is OK suggest a commit message plz.

```
