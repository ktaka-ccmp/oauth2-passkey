# Session Snapshot: Terminology Document

**Date**: 2026-01-29
**Topic**: Create a terminology/glossary document for developers

## Background

Multiple identifier terms are used throughout the library and WebAuthn ecosystem, causing confusion:

- `user_id` (database) vs `user_handle` (WebAuthn)
- `user.id`, `userHandle`, `userId` all referring to the same WebAuthn concept
- `credential_id` vs other identifiers

## Proposed Document

**Location**: `docs/src/appendix/terminology.md`

## Content Outline

### User Identifiers

| Term | Context | Description |
|------|---------|-------------|
| `user_id` | This library (DB) | Application's internal user identifier (UUID, auto-increment, etc.) |
| `user_handle` | This library (DB) | WebAuthn user identifier stored with credentials |
| `user.id` | WebAuthn registration | User identifier in `PublicKeyCredentialUserEntity` |
| `userHandle` | WebAuthn authentication | Returned in `AuthenticatorAssertionResponse` |
| `userId` | Signal API | Parameter name for user identifier |

**Key point**: `user_handle`, `user.id`, `userHandle`, and `userId` all refer to the same value. `user_id` is different - it's the application's internal identifier.

### Credential Identifiers

| Term | Context | Description |
|------|---------|-------------|
| `credential_id` | This library (DB) | Base64URL-encoded credential identifier |
| `credentialId` | WebAuthn/Signal API | Raw credential identifier |
| `id` | `PublicKeyCredential` | Same as credentialId |

### Relationship Diagram

```
Application Database:
┌─────────────────────────────────────────────┐
│ users table                                 │
│   user_id (PK) ──────────────────┐          │
│   name                           │          │
│   email                          │          │
└──────────────────────────────────│──────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────┐
│ passkey_credentials table                   │
│   credential_id (PK)                        │
│   user_id (FK) ◄─────────────────┘          │
│   user_handle ─────► WebAuthn user.id       │
│   public_key                                │
│   aaguid                                    │
└─────────────────────────────────────────────┘
```

### WebAuthn Term Aliases

```
Registration:     user.id ─────┐
                               │
Authentication:   userHandle ──┼──► Same value
                               │
Signal API:       userId ──────┘

This library:     user_handle ─┘
```

## Implementation

1. Create `docs/src/appendix/terminology.md`
2. Add to `docs/src/SUMMARY.md` under Appendices
3. Link from `user-handle-and-signal-api.md` terminology note

## Priority

Low - helpful but not blocking. Current inline note in Signal API section provides minimal clarity.
