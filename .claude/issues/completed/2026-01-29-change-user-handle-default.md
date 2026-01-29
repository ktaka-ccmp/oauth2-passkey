# Issue: Change PASSKEY_USER_HANDLE_UNIQUE default to false

## ID: 2026-01-29-01

## Status: completed

## Priority: medium

## Difficulty: small

## Description

Change `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` default from `true` to `false` for better WebAuthn spec alignment and Signal API effectiveness.

## Related Files

- `oauth2_passkey/src/passkey/config.rs` - Change default value
- `docs/src/webauthn/user-handle-and-signal-api.md` - Update documentation
- `docs/src/integration/configuration.md` - Update config reference
- `docs/src/integration/passkey.md` - Update config table
- `dot.env.example` - Update example config
- `CHANGELOG.md` - Document breaking change

## Notes

From session 2026-01-29:

**Comparison**:
| Aspect | `true` (current) | `false` (proposed) |
|--------|------------------|-------------------|
| Credentials per authenticator | Unlimited | One |
| Signal API effectiveness | Limited | Full |
| WebAuthn spec alignment | Non-standard | Aligned |
| Password manager compatibility | Workaround | Native |

**Arguments for `false`**:
1. WebAuthn spec alignment (one-user-handle-per-user)
2. Signal API works fully (`signalAllAcceptedCredentials`, `signalCurrentUserDetails`)
3. Password manager friendly
4. Simpler mental model
5. Smaller attack surface

**Risks**:
- Breaking change for existing deployments
- Users surprised when old credentials replaced
- Developers may need explicit `true` for testing

**Mitigation**:
- Clear documentation
- Migration guide in release notes
- Prominent warning about credential replacement

## Resolution

Implemented in branch `dev-2026-01-29-01`:

1. Changed default from `true` to `false` in `oauth2_passkey/src/passkey/config.rs`
2. Updated all documentation to reflect new default:
   - `docs/src/webauthn/user-handle-and-signal-api.md`
   - `docs/src/integration/configuration.md`
   - `docs/src/integration/passkey.md`
3. Updated `dot.env.example` with new default and clarified comments
4. Added BREAKING CHANGE entry in `CHANGELOG.md`

All tests pass. Existing credentials are not affected; only newly registered credentials use the new default.
