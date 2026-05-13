# Issue: Passkey register/finish falls through to create_user when auth is lost mid-flow

## Metadata

- ID: 20260513-0544
- Created: 2026-05-13-05-44
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2025` E2E Tests (surfaced this behaviour while writing
    `passkey-registration-protection.spec.ts`)

## Problem

The `register/finish` handler dispatches on `Option<AuthUser>` only:

```rust
// oauth2_passkey/src/coordination/passkey.rs
match auth_user {
    Some(session_user) => verify_session_then_finish_registration(...),
    None              => create_user_then_finish_registration(reg_data).await,
}
```

`start_registration` already distinguishes the two modes — when
`session_user` is `Some`, it caches a `SessionInfo { user }` keyed by the
generated `user_handle`; for the anonymous `create_user` flow it does
not. But `register/finish` never consults that cache to decide which
branch to take. It picks the branch based on whether the *current
request* presents valid auth.

Concrete consequence: an `add_to_user` flow whose session is lost
between `register/start` and `register/finish` silently becomes a
`create_user` flow. The credential the user just generated is bound to
a fresh orphan user account named after whatever the modal's
"username" field held at start (e.g. `username#YYYYMMDD`, defaulted by
`passkey.js`).

Observed under load test conditions: `Option<AuthUser>` resolves to
`None` whenever the AuthUser extractor fails for *any* reason — missing
cookie, cookie present but session_id unknown to the cache,
`X-CSRF-Token` header missing on a JSON POST, or `X-CSRF-Token`
mismatching the session. None of those cases are caught by the Phase 2
`SessionInfo` check, which only fires on the `Some` branch.

Server log from the reproduction (E2E `Phase 2: session swap ...` first
attempt, before switching to the `page.evaluate` approach):

```
handle_finish_registration_core{user_id=""}
upsert_user user_id=60f54b22-... user_account=would-be-evil
... sequence_number=4
```

The credential is now associated with a new user `60f54b22-...`, not
the originator. The `SessionInfo` entry under the originator's
`user_handle` is left in the cache to expire on TTL.

### Impact assessment

This is a **hardening / defense-in-depth** concern, not an exploitable
vulnerability under realistic threat models:

- An attacker cannot force the auth to be lost over a TLS-protected
  request. Cookie/header strip requires MITM on HTTPS, which is
  outside the normal threat model for this library.
- The resulting orphan account does **not** grant the attacker access
  to the originator's existing account. The attacker does not control
  the authenticator that produced the credential.
- The originator can lose access to their account in a contrived
  sequence — if the orphan user's row "wins" their authenticator's
  future `credentials.get()` lookup, they sign in as the orphan, not
  themselves. Still gated on the same MITM precondition.

What the bug *does* break is the principle "a mode declared at start
is the mode honoured at finish". `add_to_user` is a privileged-context
flow; silently downgrading it to anonymous user creation violates the
declared semantics even if no privilege escalation results.

## Timeline

### 2026-05-13T05:44 — Filed from E2E spec work

Found while building `tests-e2e/tests/passkey-registration-protection.spec.ts`.
The first attempt at Phase 2 used Playwright's `page.route` to swap
A's cookies for B's on the in-flight `register/finish`. Instead of
hitting the documented "User ID mismatch" path, the request landed in
the `create_user` branch and minted a fresh user with the credential.
Investigation showed the dispatcher does not consult `SessionInfo`
cache; whatever `Option<AuthUser>` resolves to wins. The E2E spec was
rewritten to use `page.evaluate` so it controls the auth state
properly, but the underlying dispatch is still loose.

## Latest Plan

`register/finish` has two server-controlled signals: whether a
`SessionInfo` entry exists under `reg_data.user_handle` (set at
`register/start` iff the start request was authenticated) and whether
the current request carries a valid `AuthUser`. The body's `mode`
field is client-supplied and must not enter the dispatch.

The dispatcher should be a 2×2 over those two signals:

| `SessionInfo` cached? | `AuthUser` at finish | Outcome |
|----------------------|----------------------|---------|
| No | `None` | Anonymous `create_user` registration — proceed to `create_user_then_finish_registration` |
| No | `Some(_)` | Inconsistent state (start was anonymous, finish is authenticated). Reject. Today this falls through to `verify_session_then_finish_registration` and gets `PasskeyError::NotFound("Session not found")`; the new code should reject explicitly with the same or a clearer error |
| Yes | `None` | **The bug.** Authenticated `add_to_user` flow whose auth was lost mid-round-trip. Reject explicitly (e.g. `PasskeyError::Unauthorized("add_to_user flow lost its session")`). Today: silently falls through to `create_user_then_finish_registration` and creates an orphan |
| Yes | `Some(u)` | Phase 2 path: compare `u.id == session_info.user.id`. Match → finish registration for that user. Mismatch → existing `PasskeyError::Format("User ID mismatch")` |

Implementation sketch in
`oauth2_passkey/src/coordination/passkey.rs::handle_finish_registration_core`:

```rust,ignore
// Pseudocode
let user_handle = reg_data.user_handle.as_deref().ok_or(...)?;
let session_info: Option<SessionInfo> = peek_session_info(user_handle).await?;

match (session_info, auth_user) {
    (None, None)        => create_user_then_finish_registration(reg_data).await,
    (None, Some(_))     => Err(PasskeyError::Format("Anonymous-start flow finished with active session")),
    (Some(_), None)     => Err(PasskeyError::Unauthorized("add_to_user flow lost its session")),
    (Some(info), Some(u)) => {
        if info.user.id != u.id {
            return Err(PasskeyError::Format("User ID mismatch"));
        }
        // unchanged from today: cleanup SessionInfo, finish for u
        verify_session_then_finish_registration_after_match(...)
    }
}
```

A small refactor of `verify_session_then_finish_registration` is
needed because the `SessionInfo` lookup and the comparison currently
live inside that function. The cleanest shape is to:

1. Add a `peek_session_info(user_handle) -> Option<SessionInfo>`
   helper that does the cache get without removing the entry.
2. Keep the cache *removal* paired with the actual finish step (so
   that any of the three error cells above leaves the entry in place
   for the legitimate retry, gated by the existing TTL).

The body's `mode` field continues to be ignored by the dispatcher.
The TTL of `SessionInfo` already aligns with `PASSKEY_CHALLENGE_TIMEOUT`,
so a legitimate retry within the window still works.

### Files

- `oauth2_passkey/src/coordination/passkey.rs` —
  `handle_finish_registration_core` becomes the explicit 2×2.
- `oauth2_passkey/src/passkey/main/register.rs` — extract a
  `peek_session_info` (or equivalent) helper; trim
  `verify_session_then_finish_registration` so it no longer does the
  lookup itself.
- `oauth2_passkey/src/passkey/main/register/tests.rs` — function-level
  regression tests for all four cells.
- `docs/src/security/passkey-registration-protection.md` — Phase 2
  description: dispatch is on the `(SessionInfo, AuthUser)` pair, and
  the body's `mode` is not consulted.
- `tests-e2e/tests/passkey-registration-protection.spec.ts` — add a
  third assertion covering the `(Yes, None)` cell (`register/start`
  authenticated → `register/finish` with no cookie at all → reject).

### Implementation Tasks

- [ ] Add `peek_session_info(user_handle) -> Option<SessionInfo>`
      (cache read without remove)
- [ ] Refactor `verify_session_then_finish_registration` to take a
      `SessionInfo` (or a `&SessionUser` known to match) instead of
      doing its own lookup
- [ ] Rewrite `handle_finish_registration_core` as the explicit 2×2
      match shown above
- [ ] Unit test: `(SessionInfo No, AuthUser None)` → create_user OK
- [ ] Unit test: `(SessionInfo No, AuthUser Some)` → reject (no user
      created)
- [ ] Unit test: `(SessionInfo Yes, AuthUser None)` → reject (no user
      created, SessionInfo still present for legitimate retry)
- [ ] Unit test: `(SessionInfo Yes, AuthUser Some, match)` → success
- [ ] Unit test: `(SessionInfo Yes, AuthUser Some, mismatch)` →
      "User ID mismatch" reject
- [ ] E2E follow-up in
      `passkey-registration-protection.spec.ts`: add the "no auth at
      finish after authenticated start" sub-case
- [ ] Update `docs/src/security/passkey-registration-protection.md`
      Phase 2 wording to reflect the 2×2 dispatch and the explicit
      non-trust of `body.mode`

### Verification

- `cargo test -p oauth2-passkey --lib` — five new function-level cases
  cover the matrix
- `npx playwright test passkey-registration-protection.spec.ts` —
  three Phase 2 sub-cases (existing "swap to B", existing "match",
  new "drop auth")

## Resolution

<!-- written when status moves to completed -->
