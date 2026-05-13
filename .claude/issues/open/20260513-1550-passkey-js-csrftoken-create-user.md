# Issue: passkey.js references csrfToken in create_user mode where the server does not check it

## Metadata

- ID: 20260513-1550
- Created: 2026-05-13-15-50
- Closed:
- Status: open
- Priority: medium
- Difficulty: small
- Related Issues:
  - `20260226-2025` E2E Tests (Phase 3 surfaced this while writing
    `demo-custom-login.spec.ts`; my initial response added a
    `csrfToken = "_NOT_SET_"` to the demo template, which fixes the
    symptom in that one demo but leaves the root cause — passkey.js's
    unnecessary reference — untouched)

## Problem

`oauth2_passkey_axum/static/passkey.js`'s `startRegistration` sends an
`X-CSRF-Token` header unconditionally on the two POSTs that drive
passkey registration:

```js
// passkey.js around lines 335 and 393
const startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/start', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': `${csrfToken}`,
        'Content-Type': 'application/json',
    },
    ...
});
// ...
const finishResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/finish', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': `${csrfToken}`,
        ...
    },
    ...
});
```

The handler at the server side (`handle_start_registration` /
`handle_finish_registration`) takes `Option<AuthUser>`. In
`create_user` mode the user is anonymous (no session cookie), so
`Option<AuthUser>` resolves to `None` and the AuthUser extractor's
CSRF check is **never executed** — the value of the header is
irrelevant.

But the JS still has to resolve the `csrfToken` symbol via lexical
scope to build the template literal. If the host page hasn't declared
`const csrfToken = "..."` in a `<script>` block before loading
passkey.js, the browser throws `ReferenceError: csrfToken is not
defined` at the `fetch(...)` call. The `try`/`catch` in
`startRegistration` shows an `alert("Registration failed: ...")` and
halts — visibly broken to the end user but with no clue *why* unless
the developer happens to have the browser console open.

This contract — "any page that loads passkey.js must declare a
`csrfToken` global" — is **completely undocumented**. It is
implicitly satisfied by the library's own templates
(`login.j2:20`, `user_account.j2:223`, `admin_index.j2:74`,
`admin_user_page.j2:166`), but an integrator building their own UI
has no signal that the line is required. The omission silently
breaks anonymous passkey registration; OAuth2 flows continue to work
because oauth2.js does not reference `csrfToken`.

### How it was found

While writing `tests-e2e/tests/demo-custom-login.spec.ts` (Phase 3 of
the E2E project) the spec stalled at the "Create account with
Passkey" step. Adding `page.on('console', ...)` revealed:

```
[browser:error] Error during registration: ReferenceError: csrfToken is not defined
```

`demo-custom-login/templates/login.j2` had been written without the
`const csrfToken = "...";` line that the library's built-in
`login.j2` carries. My initial response added that line to the demo
template as a symptom-level fix. It works for that one demo but does
not address the underlying issue:

- The library's `passkey.js` keeps the fragile contract.
- Any future integrator building a custom anonymous login page will
  hit the same `ReferenceError`.
- The library's own `login.j2` only carries the line as a workaround
  for the same JS pattern.

### Why this is a library bug, not a documentation gap

In `create_user` mode the server-side handler does not perform a CSRF
check; the X-CSRF-Token header is sent to satisfy a client-side JS
symbol resolution requirement that has no functional purpose. The
correct fix is to not reference the symbol in modes where the server
will not consume it.

`oauth2.js` already demonstrates the right pattern in the same
codebase — its FedCM detection uses `typeof FEDCM_ENABLED !==
'undefined' && FEDCM_ENABLED && typeof OAUTH2_CLIENT_ID !==
'undefined' && ...`. Globals that may not be declared are guarded.
Globals that the server actually requires (`csrfToken` in authed
flows) are sent. The same discipline should apply to `passkey.js`.

`O2P_ROUTE_PREFIX` is a separate undeclared-global case in both
`passkey.js` and `oauth2.js`, but in practice it is always declared
by integrators because it is obviously required for URL construction
and omitting it breaks loudly and consistently. It is intentionally
out of scope here.

## Timeline

### 2026-05-13T15:50 — Filed after Phase 3 spec-writing exposed the bug

See "How it was found" above. The demo-custom-login template patch
landed in Phase 3 commit `6ae6531`; that commit is being kept (it is
the integrator-side correct action for the existing contract), but
this issue tracks the underlying library-side fix.

## Latest Plan

Patch `passkey.js` so `csrfToken` is only referenced when the server
will actually check it.

```js,ignore
// passkey.js startRegistration (sketch)
const startHeaders = { 'Content-Type': 'application/json' };
if (mode === 'add_to_user') {
    startHeaders['X-CSRF-Token'] = csrfToken;
}
const startResponse = await fetch(
    O2P_ROUTE_PREFIX + '/passkey/register/start',
    { method: 'POST', headers: startHeaders, credentials: 'same-origin',
      body: JSON.stringify(request) },
);
// ... similarly for /passkey/register/finish
```

After this change:

- Anonymous pages (login.j2, custom login pages) never need to declare
  `csrfToken`. The implicit contract is dissolved for that audience.
- Authed pages (account.j2, admin_*.j2) continue to declare
  `csrfToken` — they already do, and they need it for their own form
  submissions independent of passkey.js.
- The `const csrfToken = "_NOT_SET_";` line in the library's built-in
  `oauth2_passkey_axum/templates/login.j2` becomes unnecessary and
  can be deleted as a cleanup.
- The same line I added to `demo-custom-login/templates/login.j2` in
  6ae6531 also becomes unnecessary and can be deleted.

### Files

- `oauth2_passkey_axum/static/passkey.js` — two fetch calls in
  `startRegistration`
- `oauth2_passkey_axum/templates/login.j2` — drop `const csrfToken =
  "_NOT_SET_";` and the surrounding workaround comment
- `demo-custom-login/templates/login.j2` — drop the same line I
  added in 6ae6531 and the comment block explaining it
- `tests-e2e/tests/demo-custom-login.spec.ts` — sanity-check the
  "authed" tests still pass with the cleanup
- `.claude/issues/open/20260226-2025-e2e-tests.md` — Timeline entry
  correcting the Phase 3 commentary

### Implementation Tasks

- [ ] Patch `passkey.js` `startRegistration` (two fetch headers)
- [ ] Remove `const csrfToken = "_NOT_SET_";` from
      `oauth2_passkey_axum/templates/login.j2`
- [ ] Remove the same line + comment from
      `demo-custom-login/templates/login.j2`
- [ ] Re-run Playwright suite — all 38 specs still green
- [ ] Manual: load `demo-custom-login`'s `/login` in a browser,
      click "Create account with Passkey", confirm registration
      succeeds without any console error
- [ ] Append a Resolution block here on commit

### Verification

End-to-end: `cd tests-e2e && npx playwright test` — the
`demo-custom-login.spec.ts` "authed" tests exercise this exact path
and would catch a regression. Add an extra-paranoid console-error
assertion (`expect(consoleErrors).not.toContain('ReferenceError')`)
if the spec doesn't already capture page errors.

Unit-level: not applicable (`passkey.js` is browser JS without a
node test rig in this repo).

## Resolution

<!-- written when status moves to completed -->
