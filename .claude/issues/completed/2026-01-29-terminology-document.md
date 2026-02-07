# Issue: Create Terminology/Glossary Document

## ID: 2026-01-29-03

## Status: completed

## Priority: low

## Difficulty: small

## Description

Create a terminology/glossary document to clarify confusing identifier terms used in WebAuthn and this library.

## Related Files

- `docs/src/appendix/terminology.md` - New file created
- `docs/src/SUMMARY.md` - Added link

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

## Resolution

Created `docs/src/appendix/terminology.md` with:
- User identifiers section explaining the difference between `user_id` and `user_handle`
- Credential identifiers section
- Session identifiers section
- OAuth2 identifiers section
- Type-safe wrappers reference
- Common confusion points with examples
- ASCII diagram showing database relationships
- Links to related documentation

Added to SUMMARY.md in the Appendices section.
