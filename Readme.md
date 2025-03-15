# axum-oauth2-passkey

## Todo

- Middleware based page protection i.e. create a likes of is_authorized middleware.
- Consolidate liboauth2, libpasskey, libsession and libstorage into libauth.
- ~~Examine if we should use OAuth2Coordinator and PasskeyCoordinator.~~
- ~~Autofill user.name as default values for Passkey register dialog's name and display name.~~
- ~~Related Origin Requests
(https://passkeys.dev/docs/advanced/related-origins/)~~
- ~~Use parseCreationOptionsFromJSON and parseAuthenticationOptionsFromJSON to simplify passkey.js implementation.~~ Won't do as this requires webauthn-json dependency.
- ~~Deal with halfway registration and authentication in passkey.js.~~
- Enable modification of User.account and User.label for logged in user.
- Enable deletion of Passkey credential for logged in user.
  - Passkey sync between RP and Authenticator using Signal API.
- Enable unlinking of OAuth2 account for logged in user.
