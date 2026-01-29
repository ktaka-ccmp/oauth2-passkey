# Issue: Create Terminology/Glossary Document

## ID: 2026-01-29-03

## Status: open

## Priority: low

## Description

Create a terminology/glossary document to clarify confusing identifier terms used in WebAuthn and this library.

## Related Files

- `docs/src/appendix/terminology.md` - New file to create
- `docs/src/SUMMARY.md` - Add link
- `docs/src/webauthn/user-handle-and-signal-api.md` - Link from terminology note

## Notes

From session 2026-01-29:

**Confusing Terms**:
- `user_id` (database) vs `user_handle` (WebAuthn)
- `user.id`, `userHandle`, `userId` all refer to same WebAuthn concept
- `credential_id` vs other identifiers

**Key Clarifications**:
| Term | Context | Description |
|------|---------|-------------|
| `user_id` | This library (DB) | Application's internal user identifier |
| `user_handle` | This library (DB) | WebAuthn user identifier stored with credentials |
| `user.id` | WebAuthn registration | User identifier in PublicKeyCredentialUserEntity |
| `userHandle` | WebAuthn authentication | Returned in AuthenticatorAssertionResponse |
| `userId` | Signal API | Parameter name for user identifier |

**Note**: `user_handle`, `user.id`, `userHandle`, `userId` = same value. `user_id` is different.

**Credential Identifiers**:
| Term | Context | Description |
|------|---------|-------------|
| `credential_id` | This library (DB) | Base64URL-encoded credential identifier |
| `credentialId` | WebAuthn/Signal API | Raw credential identifier |
| `id` | `PublicKeyCredential` | Same as credentialId |

**Relationship Diagram**:
```
Application Database:
┌─────────────────────────────────────────────┐
│ users table                                 │
│   user_id (PK) ──────────────────┐          │
│   name, email                    │          │
└──────────────────────────────────│──────────┘
                                   ▼
┌─────────────────────────────────────────────┐
│ passkey_credentials table                   │
│   credential_id (PK)                        │
│   user_id (FK) ◄─────────────────┘          │
│   user_handle ─────► WebAuthn user.id       │
│   public_key, aaguid                        │
└─────────────────────────────────────────────┘

WebAuthn Term Aliases:
  Registration:   user.id ────┐
  Authentication: userHandle ─┼──► Same value
  Signal API:     userId ─────┘
  This library:   user_handle ┘
```

## Resolution

