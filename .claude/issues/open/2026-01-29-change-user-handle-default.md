# Issue: Change PASSKEY_USER_HANDLE_UNIQUE default to false

## Status: open

## Priority: medium

## Description

Change `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` default from `true` to `false` for better WebAuthn spec alignment and Signal API effectiveness.

## Related Files

- `oauth2_passkey/src/env_var.rs` - Change default value
- `docs/src/webauthn/user-handle-and-signal-api.md` - Update documentation
- `dot.env.example` - Update example config

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

