# Session Snapshot: SESSION_CONFLICT_POLICY Default Consideration

**Date**: 2026-01-29
**Topic**: Should `SESSION_CONFLICT_POLICY` default change from `allow` to `replace`?

## Current State

Default is `allow` (permit multiple concurrent sessions).

## Options

| Policy    | Behavior                                      | Use Case                        |
|-----------|-----------------------------------------------|---------------------------------|
| `allow`   | Multiple concurrent sessions permitted        | General web apps                |
| `replace` | Old sessions invalidated on new login         | Security-sensitive apps         |
| `reject`  | Login denied if session exists                | High-security environments      |

## Comparison for Default Selection

| Aspect                    | `allow` (current)              | `replace` (proposed)           |
|---------------------------|--------------------------------|--------------------------------|
| User experience           | Seamless multi-device          | May surprise users on old device|
| Security                  | Lower (sessions accumulate)    | Higher (only one session)      |
| Complexity for users      | None                           | Need to understand behavior    |
| Session hijacking risk    | Higher (more sessions = more targets) | Lower (auto-cleanup)    |
| Account sharing           | Easy                           | Difficult                      |

## Arguments for Keeping `allow` as Default

1. **Least surprising**: Users expect to stay logged in on multiple devices
2. **Standard behavior**: Most web apps allow concurrent sessions
3. **Library philosophy**: Provide flexibility, let apps choose restrictions
4. **No breaking change**: Existing deployments continue working

## Arguments for `replace` as Default

1. **Security by default**: Limits attack surface automatically
2. **Auto-cleanup**: Prevents session accumulation
3. **Single-session clarity**: Easier to reason about
4. **Common in auth libraries**: Many security-focused libs use this

## Analysis

Unlike `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` which has technical implications (Signal API effectiveness), `SESSION_CONFLICT_POLICY` is purely a business/security decision:

- **User handle strategy**: Technical choice that affects WebAuthn specification compliance
- **Session conflict policy**: Business choice that varies by application requirements

## Recommendation

**Keep `allow` as default** for the following reasons:

1. **Business decision**: This is not a technical correctness issue but an application policy
2. **Existing behavior**: Changing would break user expectations for existing deployments
3. **Library role**: A library should provide flexibility; the application decides policy
4. **Documentation**: Already well-documented with clear guidance on when to use each option

## Alternative: Documentation Enhancement

Instead of changing the default, enhance documentation to:

1. Highlight `replace` as recommended for security-sensitive applications
2. Add a "Security Recommendations" section suggesting `replace` for production
3. Include in security checklist for production deployment

## Conclusion

No change recommended. The current default of `allow` is appropriate for a general-purpose library. Applications with stricter security requirements can easily set `replace`.

This differs from the user_handle case where:
- User handle affects technical correctness (Signal API behavior)
- Session policy is purely a business/UX decision
