# Issue: Simplify OAuth2 Account Linking API

## Metadata

- ID: 20260226-2018
- Created: 2026-02-26-20-18
- Closed: 2026-05-12-15-39
- Status: wontfix
- Priority: low
- Difficulty: medium
- Related Issues:
  - `20260512-0335` POST-based OAuth2 account linking initiation (Alt 5B validation) (child — closed as wontfix 2026-05-12, determined this issue's outcome)

## Problem

The current OAuth2 account linking implementation creates a significant barrier to adoption due to its complexity. Users must understand and coordinate multiple concepts (CSRF tokens, page session tokens) and make multiple API calls (~50+ lines of code) to accomplish what should be a simple operation.

### Current Complexity

1. Call `/auth/user/csrf_token` to get CSRF token
2. Call `generate_page_session_token(&csrf_token)` for security token
3. Construct OAuth2 URL with `mode=add_to_user&context=${page_session_token}`
4. Handle popup window management and session verification

### Goal

Provide a simpler, more intuitive API that reduces the integration burden while maintaining security guarantees.

## Timeline

### 2026-02-26T20:18 — Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as high-priority issue; design proposal already exists
- Reason: This is a key usability barrier for library adoption

### 2026-05-12T02:46 — Re-evaluation after deep code/docs review

Investigation of `oauth2_passkey/src/coordination/oauth2.rs`,
`oauth2_passkey_axum/src/oauth2.rs`,
`oauth2_passkey_axum/src/user/account.rs`,
`oauth2_passkey_axum/static/oauth2.js`,
`oauth2_passkey/src/session/main/page_session_token.rs`, and
`docs/src/security/page-session.md` revises the Problem framing as
follows.

**Current ergonomics are better than the Problem section suggests.**
The "~50+ lines" figure reflects an integration-test helper
(`tests/integration/oauth2_flows.rs:135`), not real application code.
In practice:

- Using the built-in `/user/account` page: 0 lines of library-user
  code. `user/account.rs:96` already calls
  `generate_page_session_token(&user.csrf_token)` internally;
  `templates/user_account.j2:135` wires the button via
  `oauth2.openSelectPopup('add_to_user', PAGE_SESSION_TOKEN)`.
- Writing a custom UI: ~3 lines.
  1. `let page_session_token = generate_page_session_token(&auth_user.csrf_token);`
  2. Pass to template as a variable.
  3. `<button onclick="oauth2.openSelectPopup('add_to_user', '{{ page_session_token }}')">`

`AuthUser.csrf_token` is already a public field
(`oauth2_passkey_axum/src/session.rs:91`); there is no need to call
`/auth/user/csrf_token` from server-side code.

**The page_session_token mechanism itself is sound and not
removable.** OAuth2 initiation is a navigation (`window.open`), not
a `fetch`, so custom headers cannot ride along. Cookies alone are
insufficient because the session-boundary attack
(`docs/src/security/page-session.md:14-29`) is precisely the case
where the cookie has been switched. A URL query parameter is the
only practical channel. The HMAC-SHA256 obfuscation
(`page_session_token.rs:48-54`) prevents the session CSRF token from
leaking via Referer / browser history / server logs while keeping
verification stateless.

**Implication for this issue's recommended approaches.** The
archived design proposal's flagship suggestions are problematic on
re-reading:

- `auth_user.create_oauth2_link_url("google").await` — `.await`
  has no justification (the operation is a pure HMAC); also couples
  the session/identity type to a provider string.
- `auth_user.link_google_account()` trait methods — provider-name
  baked into method signatures, regressing the current multi-
  provider design (Google, Auth0, Entra, Keycloak, generic OIDC
  slots).
- Builder pattern / middleware approaches — overkill given the
  actual cost of the current flow.

**What an ergonomics improvement could look like.** A small free
function helper, e.g.

```rust
// oauth2_passkey_axum::oauth2
pub fn oauth2_link_url(user: &AuthUser, provider: &str) -> String {
    let token = generate_page_session_token(&user.csrf_token);
    format!("{}/oauth2/{provider}?mode=add_to_user&context={token}",
            O2P_ROUTE_PREFIX.as_str())
}
```

Sync, no provider coupling on `AuthUser`, saves 1–2 lines per
custom-UI handler. Pair with a short documentation chapter
("Building a custom OAuth2 linking UI") under `docs/src/guides/`
or `docs/src/integration/`.

**Side findings (not in scope for this issue, to be filed
separately).**

- `verify_page_session_token` at
  `oauth2_passkey/src/session/main/page_session_token.rs:107` uses
  `!=` to compare HMACs. `docs/src/security/csrf.md:132-146`
  mandates constant-time comparison (`subtle::ConstantTimeEq`) for
  CSRF token comparisons; the page_session_token check is
  inconsistent with the project's own stated policy. Practical
  risk is low (Rust string `==` typically delegates to memcmp,
  and the HMAC output is 32 bytes so byte-by-byte search is not
  meaningful) but the inconsistency is worth fixing.
- `docs/src/archived/README.md:28-37` lists
  `oauth2-account-linking-api-simplification.md` under "Implemented
  design documents and proposals", which is incorrect — no part of
  the proposal has been implemented. Should be moved to a
  "Withdrawn" or "Not implemented" category, or annotated inline.
- The naming `page_session_token` is jargon and obscures the
  purpose (OAuth2-linking-specific session-boundary proof). Worth
  considering a clearer name in a future API revision, though
  this would be a breaking change.

**Re-evaluation of priority.** The original Priority `high` rests
on the framing "key usability barrier for library adoption". Given
that the built-in account page already provides zero-configuration
account linking and custom UIs require only 3 lines, the real
usability barrier is smaller than the original framing implied.
Downgrading priority should be considered when the Latest Plan is
revised.

### 2026-05-12T03:21 — Meta: issue scope mis-framing

This issue and the underlying design proposal were framed as
"how do we wrap the current mechanism with a simpler API",
but should have been framed as "is the current architectural
choice (GET-based initiation + URL-embedded HMAC token) the
right one in the first place".

The proposal enumerated 5 wrapper API patterns (one-function,
builder, trait, middleware, embedded JS), all sugar over the
existing mechanism. Its concluding line ("complexity should be
hidden, not eliminated") admits the framing: complexity was
treated as load-bearing without re-examining whether it was.

The deeper question the issue should have led with: which of
the user-facing concepts (`csrf_token`, `page_session_token`,
URL query mode/context, popup mgmt) are essential to the
security goal vs. artifacts of the GET-navigation choice?
`page_session_token` is the latter — it exists *because* the
flow is initiated by `window.open(url)` rather than a
CSRF-protected POST.

A POST-based linking initiation (Alt 5 in the 2026-05-12T02:46
entry) would eliminate the `page_session_token` concept
entirely, reusing the existing CSRF token mechanism. This is
the architectural alternative the original proposal did not
consider.

This entry records that the alternative exists and that the
issue's framing should encompass it. Concrete viability of
Alt 5 (popup blocker behavior, migration cost, browser quirks
with form target) requires its own investigation and is not
decided here.

### 2026-05-12T03:42 — Plan revision: split Alt 5B; await child decision

Snapshot of previous Latest Plan before overwriting (per
`.claude/issues/README.md` L259 — substantive Latest Plan revisions
must copy the previous body into Timeline first):

> See detailed analysis and proposed solutions in
> `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`.
>
> ### Files
>
> - `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`
> - `oauth2_passkey/src/coordination/oauth2.rs`
> - `oauth2_passkey_axum/src/oauth2.rs`
>
> ### Implementation Tasks
>
> - [ ] Review existing design proposal
> - [ ] Design simplified API surface
> - [ ] Implement simplified account linking flow
> - [ ] Update documentation and examples
> - [ ] Add integration tests for new API
>
> ### Verification

Reason for revision: the 2026-05-12T02:46 and T03:21 Timeline entries
established that (a) the archived design proposal's framing is wrong,
and (b) the real architectural question — eliminating
`page_session_token` via POST-based initiation — has been split out
to issue `20260512-0335` (Alt 5B validation). The new Latest Plan
reflects this dependency and defines the fallback path for the
no-go case. Priority was also downgraded `high` → `low` at this
revision; active work has moved to the child issue, and the
remaining parent scope is either auto-closure (Alt 5B go) or a
small helper + docs (Alt 5B no-go).

### 2026-05-12T04:09 — Plan revision: add Always section for docs restructure; refine "If go" wording

Snapshot of previous Latest Plan before overwriting (per
`.claude/issues/README.md` L259):

> This issue's resolution is now conditional on the outcome of issue
> `20260512-0335` (Alt 5B validation):
>
> ### If Alt 5B is go
>
> This issue is effectively superseded. POST-based initiation
> eliminates `page_session_token` from the user-facing API entirely,
> which is a stronger and cleaner simplification than anything in the
> archived design proposal. Action: close this issue as `completed`
> with a Resolution pointing to the implementation under
> `20260512-0335`.
>
> ### If Alt 5B is no-go
>
> Fall back to a small ergonomics improvement for custom-UI authors.
> Concrete scope:
>
> 1. Add a free helper function in `oauth2_passkey_axum::oauth2`:
>
>    ```rust
>    pub fn oauth2_link_url(user: &AuthUser, provider: &str) -> String {
>        let token = generate_page_session_token(&user.csrf_token);
>        format!("{}/oauth2/{provider}?mode=add_to_user&context={token}",
>                O2P_ROUTE_PREFIX.as_str())
>    }
>    ```
>
>    Sync (HMAC is sync, no `.await` warranted), free function (not
>    coupled to `AuthUser` type), no provider-specific trait methods.
>
> 2. Document the custom-UI linking pattern in `docs/src/guides/` or
>    `docs/src/integration/`.
>
> 3. Update `docs/src/archived/README.md:28-37` to remove
>    `oauth2-account-linking-api-simplification.md` from the
>    "Implemented design documents" list (it was never implemented in
>    either outcome), and annotate the proposal itself as superseded
>    by this issue's Timeline analysis.
>
> The archived design proposal's specific API recommendations
> (`auth_user.create_oauth2_link_url("google").await`, trait methods,
> builder pattern, middleware) are **not** part of either outcome —
> see Timeline entry 2026-05-12T02:46 for the critique.
>
> ### Files (conditional on no-go fallback)
>
> - `oauth2_passkey_axum/src/oauth2.rs` — add `oauth2_link_url` helper
> - `docs/src/guides/` or `docs/src/integration/` — new chapter on
>   building a custom OAuth2 linking UI
> - `docs/src/archived/README.md` — correct the "Implemented" mislabel
> - `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`
>   — add "Status: superseded" note at top
>
> ### Implementation Tasks
>
> - [ ] Await go/no-go decision from `20260512-0335`
> - [ ] If no-go: add `oauth2_link_url` helper with unit tests
> - [ ] If no-go: write custom-UI linking guide chapter
> - [ ] If no-go: correct `archived/README.md` mislabel and annotate
>        the design proposal as superseded
> - [ ] If go: close as `completed` with Resolution pointing to
>        `20260512-0335`
>
> ### Verification
>
> - If go path: covered by `20260512-0335` Verification.
> - If no-go path: `cargo test --manifest-path oauth2_passkey_axum/Cargo.toml
>   --all-features` plus manual walkthrough of the new custom-UI guide
>   against `demo-both`.

Reasons for revision:

1. **Add Always section.** Docs restructure of
   `docs/src/security/page-session.md` is independent of Alt 5B
   outcome and proceeds now. The current document presents two
   attack scenarios then dives into ~100 lines of Phase 1 details
   before introducing Phase 2 (misc_session) — the unifying
   Phase-Specific Protection table sits at the very end. The new
   "Always (independent of Alt 5B outcome)" section captures this
   restructure as work to be done immediately.

2. **Refine "If Alt 5B is go" wording.** Previous wording said
   POST-based initiation "eliminates `page_session_token` from the
   user-facing API entirely". Per session discussion, the GET path
   and `page_session_token` mechanism are kept indefinitely as a
   backward-compat alternative (consistent with `20260512-0335`'s
   coexistence design and migration plan). The concept therefore
   does not "entirely" disappear — it ceases to be the leading
   example in docs and APIs.

3. **Move archived-README labeling out of no-go fallback.** This
   item is now its own issue `20260512-0351` and proceeds
   independently. Removed from the no-go fallback list to avoid
   duplication.

### 2026-05-12T04:54 — Side effect: passkey doc spawned

During the docs restructure executed under the Always section, it
became clear that the previous `page-session.md` mentioned passkey
registration in its threat description but did not actually cover
passkey's protection mechanism. Investigation confirmed that the
library protects passkey registration with `X-CSRF-Token` header
(Phase 1) and a `user_handle`-keyed `SessionInfo` cache entry with
explicit user ID comparison at finish (Phase 2) — functionally
equivalent to the OAuth2 protections, implemented differently
because passkey registration is initiated by a `fetch` POST rather
than a `window.open(...)` navigation.

Rather than expanding the OAuth2 doc back out to cover both flows,
a parallel `docs/src/security/passkey-registration-protection.md`
was created (mirroring the OAuth2 doc's structure), a SUMMARY.md
entry added, and a cross-reference inserted in
`oauth2-linking-protection.md`'s Process Start-to-Completion
subsection. This work was tangential to the parent issue's scope
(OAuth2 linking simplification) but landed in the same branch.

The Always-section scope of this parent issue is unchanged; this
entry records the side-effect for traceability.

### 2026-05-12T15:39 — Decision: close as wontfix

Closing the issue.

Child `20260512-0335` (Alt 5B / POST-based linking validation)
landed at commit `ca62953` end-to-end (env var
`OAUTH2_LINKING_MODE`, `POST /oauth2/{provider}`,
`POST /oauth2/select`, `select_provider.j2` branch,
`oauth2.linkAccountPost` / `oauth2.startLinkingViaForm` JS API)
and was then reverted at `f13d247` as wontfix. The negative
result is preserved in dev's git history and the child issue's
Timeline (T03:35 through T15:26). The conclusion was that POST
mode delivers no meaningful value over GET — same security
coverage, page_session_token still needed for the GET default,
zero user-visible change at the built-in /user/account page,
permanent two-path maintenance cost.

That outcome also undermines this parent issue's framing. The
parent originally claimed (per archived design proposal) that
OAuth2 account linking required ~50+ lines of integration code
and was "a key usability barrier for library adoption". The
2026-05-12T02:46 re-evaluation entry already established that
the 50+ figure came from an integration-test helper, not real
application code: with the built-in `/user/account` page, a
library user writes 0 lines; with a custom UI, ~3 lines. Alt
5B was the strongest concrete remediation candidate this issue
produced. Its failure isn't a setback for "simplify OAuth2
linking" — it's evidence that there's no real complexity to
simplify.

The Latest Plan's "Always" section (docs restructure of
`page-session.md` → `oauth2-linking-protection.md`) was
already executed and merged via PR #341. The "If Alt 5B is
no-go" fallback was a small free-function helper
(`oauth2_link_url`) plus a custom-UI guide chapter; per the
analysis above the helper saves ~1 line per custom-UI handler,
which doesn't justify the public-API surface area, and the
guide is something to write only if there's documented user
demand. Neither will be acted on by this issue.

What remains unaddressed in the broader "OAuth2 account
linking" space — if any reader reaches this Timeline looking
for follow-up work:

- **No outstanding bugs.** Current GET-based flow is
  production-tested via the demo apps and integration tests.
- **No outstanding security issues.** GET-mode threat coverage
  is documented in `docs/src/security/oauth2-linking-protection.md`
  (the doc that this issue's "Always" section produced); Alt
  5B was the alternative-architecture investigation and is now
  closed out.
- **No outstanding ergonomics issues.** The 3-line custom-UI
  case is well within library conventions. If a future
  contributor finds the friction worth removing they can open
  a fresh issue with the concrete use case.

Closing as `wontfix` rather than `completed` because nothing in
the original Implementation Tasks list shipped on this issue
specifically — Always-section docs work landed via the same
branch but is attributed there; the conditional fallback is
declined; Alt 5B (the actual exploration this issue spawned)
went to its own issue and was closed wontfix.

The Latest Plan below is left unchanged as a historical
artifact of the design exploration. The authoritative outcome
is in this Timeline entry and the Resolution section.

## Latest Plan

Scope is split into work that proceeds regardless of Alt 5B's
outcome, and conditional work that depends on the child issue
`20260512-0335`.

### Always (independent of Alt 5B outcome)

**Restructure `docs/src/security/oauth2-linking-protection.md`
(renamed from `page-session.md`) for a clearer conceptual map and
more accurate scope framing.** The previous document title and
intro led with Phase 1's mechanism, making Phase 2 read as
supplementary; the unifying phase-mapping table sat at the very
end. Rename file and title, rewrite Overview, and reorder
sections so readers see the two-phase model up front.

Restructure target:

1. Rename file to `oauth2-linking-protection.md` and update H1 to
   "OAuth2 Linking Session Protection".
2. Overview — rewrite to introduce the two-phase model and
   incorporate the phase-mapping table directly (no separate
   "Two-Phase Protection Overview" section).
3. Session Boundary Attacks (unchanged).
4. **Phase 1: Page Session Token Mechanism** — consolidate the
   former "Page Session Token Mechanism" + "Token Generation and
   Verification" sections; add a brief intro paragraph explaining
   the `window.open` navigation constraint that motivates the
   mechanism.
5. **Phase 2: OAuth2 Flow Session Continuity** — rename
   "Integration with OAuth2 Flows"; add an intro paragraph framing
   the IDP round-trip threat.
6. Implementation Notes — short summary of remaining items from
   the former "Key Security Characteristics".
7. **Testing Session Protection** — rename and split into
   "Phase 1: Page-to-Request Detection" + "Phase 2: OAuth2 Flow
   Continuity" subsections.

Code blocks are preserved verbatim; prose is lightly rewritten
for smoother transitions where new section intros were added.

### If Alt 5B is go

POST-based initiation becomes the recommended default. The GET
path and `page_session_token` mechanism are kept as a
backward-compat alternative (controlled by `O2P_LINKING_MODE`, see
child issue `20260512-0335` migration plan), so the concept does
not disappear from the codebase — it simply ceases to be the
leading example in docs and APIs.

Action: close this issue as `completed` with a Resolution pointing
to the implementation under `20260512-0335`. The docs restructure
from the Always section is incorporated regardless.

### If Alt 5B is no-go

Fall back to a small ergonomics improvement for custom-UI authors.
Concrete scope:

1. Add a free helper function in `oauth2_passkey_axum::oauth2`:

   ```rust
   pub fn oauth2_link_url(user: &AuthUser, provider: &str) -> String {
       let token = generate_page_session_token(&user.csrf_token);
       format!("{}/oauth2/{provider}?mode=add_to_user&context={token}",
               O2P_ROUTE_PREFIX.as_str())
   }
   ```

   Sync (HMAC is sync, no `.await` warranted), free function (not
   coupled to `AuthUser` type), no provider-specific trait methods.

2. Document the custom-UI linking pattern in `docs/src/guides/` or
   `docs/src/integration/`. This complements the restructured
   `oauth2-linking-protection.md` from the Always section.

Archived design proposal status labeling is tracked separately
under `20260512-0351`; not duplicated here.

The archived design proposal's specific API recommendations
(`auth_user.create_oauth2_link_url("google").await`, trait methods,
builder pattern, middleware) are **not** part of either outcome —
see Timeline entry 2026-05-12T02:46 for the critique.

### Files

Always:

- `docs/src/security/oauth2-linking-protection.md` — restructure (renamed from `page-session.md`)

Conditional on no-go fallback:

- `oauth2_passkey_axum/src/oauth2.rs` — add `oauth2_link_url` helper
- `docs/src/guides/` or `docs/src/integration/` — new chapter on
  building a custom OAuth2 linking UI

### Implementation Tasks

- [x] Always: restructure `docs/src/security/oauth2-linking-protection.md` (renamed from `page-session.md`)
- [x] Always: verify `mdbook build docs` is warning-clean
- [ ] Await go/no-go decision from `20260512-0335`
- [ ] If no-go: add `oauth2_link_url` helper with unit tests
- [ ] If no-go: write custom-UI linking guide chapter
- [ ] If go: close as `completed` with Resolution pointing to
       `20260512-0335`

### Verification

- Always: `mdbook build docs` clean; manual readthrough of
  restructured `oauth2-linking-protection.md` reads top-to-bottom
  with the conceptual map established before details.
- If go path: covered by `20260512-0335` Verification.
- If no-go path: `cargo test --manifest-path oauth2_passkey_axum/Cargo.toml
  --all-features` plus manual walkthrough of the new custom-UI guide
  against `demo-both`.

## Resolution

Closed as `wontfix`. Full reasoning in Timeline entry
2026-05-12T15:39.

In short: the design exploration that this issue spawned
concluded that OAuth2 account linking is not in fact complex
enough to require simplification. Child issue `20260512-0335`
prototyped the strongest concrete remediation candidate
(POST-based linking, Alt 5B); it worked but added cost without
net benefit and was reverted (commit `f13d247`, history
preserved). The fallback "small helper + docs" path was also
declined for the same reason — there's no observed friction
that justifies expanding the public API.

What did land from this issue's branch family:

- Docs restructure: `page-session.md` was renamed to
  `oauth2-linking-protection.md` with a two-phase conceptual
  overview moved to the top (PR #341).
- Sibling passkey doc: `passkey-registration-protection.md`
  was authored as the parallel for passkey registration's
  session-boundary protection (separate session, committed
  via PR #341's branch).
- Side findings extracted to their own issues:
  - `20260512-0350` constant-time comparison fix (completed)
  - `20260512-0351` archived-proposals status labeling
    (completed)
  - `20260512-0457` rust,ignore standardization across docs
    (completed)
- The archived design proposal itself
  (`oauth2-account-linking-api-simplification.md`) was moved
  to the "Superseded / Not Implemented" section of
  `docs/src/archived/README.md` and got a Status notice
  pointing at this issue and `20260512-0335`.

Net effect on the codebase: pure improvements (docs hygiene,
security policy compliance, design-proposal labeling
correctness) plus a documented negative result. No
user-facing API change.
