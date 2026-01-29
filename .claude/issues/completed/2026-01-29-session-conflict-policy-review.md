# Issue: Review SESSION_CONFLICT_POLICY Default

## Status: completed

## Priority: low

## Description

Evaluate whether `SESSION_CONFLICT_POLICY` default should change from `allow` to `replace` for improved security.

## Related Files

- `oauth2_passkey/src/env_var.rs` - SESSION_CONFLICT_POLICY configuration
- `docs/src/security/sessions.md` - Session documentation

## Notes

**Options Evaluated**:
| Policy | Behavior | Use Case |
|--------|----------|----------|
| `allow` | Multiple concurrent sessions | General web apps |
| `replace` | Old sessions invalidated | Security-sensitive apps |
| `reject` | Login denied if session exists | High-security environments |

**Arguments for keeping `allow`**:
1. Least surprising - users expect multi-device login
2. Standard behavior for most web apps
3. Library philosophy: provide flexibility, let apps choose
4. No breaking change

**Arguments for `replace`**:
1. Security by default
2. Auto-cleanup of sessions
3. Common in security-focused libs

**Key Insight**:
Unlike `PASSKEY_USER_HANDLE_UNIQUE` (technical correctness issue affecting Signal API), session policy is purely a business/UX decision that varies by application requirements.

## Resolution

Completed 2026-01-29. Decision: **Keep `allow` as default**.

Rationale:
- Business decision, not technical correctness
- Library should provide flexibility
- Already well-documented with guidance
- Apps needing stricter security can set `replace`

No code changes required.
