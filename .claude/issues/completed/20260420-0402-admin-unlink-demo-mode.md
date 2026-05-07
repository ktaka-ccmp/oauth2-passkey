# Issue: Admin unlink/delete fails in demo mode ("Invalid user ID")

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-0402

## Created: 2026-04-20-04-02

## Closed: 2026-05-07

## Status: completed

## Priority: medium

## Difficulty: small

## Description

In demo mode (`O2P_DEMO_MODE=true`), an admin viewing another user's
detail page and clicking **Unlink** on an OAuth2 account (or **Delete**
on a passkey credential) sees:

> Failed to unlink account: Invalid user ID: User ID contains invalid characters

Reproduced on demo-both with `O2P_DEMO_MODE=true`, viewing a target
user whose id differs from the admin's (the masking path
`Masker::for_detail` activates only in that case).

### Mechanism

`Masker::for_detail` (`admin/masking.rs:44-48`) is active when
`*O2P_DEMO_MODE && viewer_id != target_id`. When active, the
`TemplateAccount`/`TemplateCredential` `.masked()` impls
(`admin/optional.rs:155-156`, `:185-187`) replace these resource
identifiers with first-four-chars + `"***"`:

- `credential.credential_id`, `credential.user_id`,
  `credential.user_handle`
- `account.id`, `account.user_id`, `account.provider_user_id`

Both action paths feed those masked values back into write handlers:

- **Unlink OAuth2** (`templates/admin_user_page.j2:138`) embeds
  `provider_user_id` + `user_id` into the onclick handler, JS posts
  `DELETE /admin/delete_oauth2_account/{provider}/{provider_user_id}`
  with `user_id` in the body.
- **Delete passkey** (`templates/admin_user_page.j2:97`) embeds
  `credential_id` + `user_id`, JS posts
  `DELETE /admin/delete_passkey_credential/{credential_id}` with
  `user_id` in the body.

The handlers call `UserId::new` / `ProviderUserId::new` /
`CredentialId::new`, all of which reject `*` (the masking marker
character is not in any of their allowed character sets). The
user-visible failure surfaces from whichever validator runs first —
currently `UserId::new`, hence the "Invalid user ID" message.

The other admin write actions on the same page (`DeleteAccount`
button at L21, `toggleAdminStatus` at L37, `forceLogout` at L49)
bind to `user.id`, which is **not** masked
(`Masker::mask_user` only touches `account` and `label`,
`masking.rs:81-90`). Those work correctly.

### Why this is a design conflict, not a parsing bug

Earlier diagnoses (see Decision Log entries dated 2026-04-20) framed
this narrowly as a `user_id` parsing problem solvable by switching
the handlers to admin-level coordination functions. End-to-end
tracing of that proposed fix revealed it would only change the error
message from `"Invalid user ID"` to `"Invalid provider user ID"` /
`"Invalid credential ID"` because the same `*`-rejecting validators
sit on the URL-path side as well.

The deeper issue: demo mode masking exists to hide other users'
identifiers from the demo viewer, but those identifiers are
required verbatim to perform write actions. You cannot honor both
"viewer cannot see X" and "viewer can act on X" on the same page
unless X round-trips outside the masking boundary (a cleartext side
channel) — which would defeat the masking.

## Related Issues

- `20260220-2357` Full Masking for Email and Name in Demo Mode
  (relationship: introduced the masker used here; masking itself is
  correct — this issue is about the action-button layer)

## Approach

Accept the design conflict and resolve it on the UX side: when the
detail-page masker is active, disable the destructive actions that
operate on per-resource items.

1. **Surface the masker activity to the template**. Expose a
   `Masker::is_active() -> bool` accessor (currently the `active`
   field is private), and pass `actions_disabled: bool` into
   `AdminUserPageTemplate`, set from `masker.is_active()` at the
   single construction site (`admin/optional.rs:313`).

2. **Disable the affected buttons**. In
   `templates/admin_user_page.j2`, gate L97 (delete passkey) and
   L138 (unlink oauth2) on `actions_disabled`:

   ```jinja2
   <button onclick="..."
           class="delete-button"
           {% if actions_disabled %}disabled
           title="Disabled in demo mode for other users' data"
           {% endif %}>...</button>
   ```

   Disable rather than hide so the demo still demonstrates these
   capabilities exist; the tooltip explains why they are inert.

**Defense-in-depth**: The `*Id::new` validators reject masked-format
strings with HTTP 400, which is the correct response if a future
caller bypasses the disabled UI. This is intended behavior, not
an accidental side-effect.

**Out of scope**: switching the handlers to admin-level coordination
functions (`delete_oauth2_account_admin` /
`delete_passkey_credential_admin`) and removing the `user_id`
request-body round-trip. See the 2026-05-07 Decision Log entry for
the trade-off; the round-trip retains a small fail-safe value
against template-DB skew so it stays for now.

## Related Files

- `oauth2_passkey_axum/src/admin/masking.rs` (add `is_active`)
- `oauth2_passkey_axum/src/admin/optional.rs` (template struct +
  masker construction at L313)
- `oauth2_passkey_axum/templates/admin_user_page.j2` (gate L97 +
  L138)
- `oauth2_passkey_axum/static/admin_user.js` (read-only —
  intentionally untouched, see 2026-05-07 scope decision)
- `oauth2_passkey_axum/src/admin/default.rs` (read-only —
  intentionally untouched, see 2026-05-07 scope decision)

## Implementation Tasks

- [x] Add `Masker::is_active(&self) -> bool` accessor
- [x] Add `actions_disabled: bool` to `AdminUserPageTemplate`,
      populate from `masker.is_active()`
- [x] Gate the two button onclick handlers in `admin_user_page.j2`
      on `actions_disabled`
- [x] `cargo fmt --all && cargo clippy --all-targets --all-features
      && cargo test`
- [x] Manual verification with `O2P_DEMO_MODE=true`: button
      disabled with tooltip when admin views another user, working
      when admin views self
- [x] Manual regression check with `O2P_DEMO_MODE` unset: button
      enabled and operation succeeds

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Use admin-level coordination fns instead of patching masking

- Context: Initial instinct was to leave the masking alone and instead
  exempt `user_id` from masking for admin forms. That would keep the
  buggy API call shape and punch a hole in demo-mode privacy.
- Decision: Switch the two admin handlers to
  `delete_oauth2_account_admin` / `delete_passkey_credential_admin`,
  which match the pattern used by the other admin handlers in the
  same file (`delete_user_account_handler`,
  `update_admin_status_handler`).
- Reason: Eliminates the `user_id` round-trip entirely, matches the
  existing "admin-level coordination fn" pattern in the crate, and
  does not compromise demo-mode masking. Security posture improves
  slightly (fresh-DB admin check in the coordination layer).

### 2026-04-20: Keep `provider` in the URL but drop it from body plumbing

- Context: `delete_oauth2_account_admin` matches on
  `provider_user_id` alone (`AccountSearchField::ProviderUserId`) and
  does not need `provider`.
- Decision: Keep the `{provider}` path segment in the route
  (`/admin/delete_oauth2_account/{provider}/{provider_user_id}`);
  bind it to `_provider` in the handler.
- Reason: URL stability for operator bookmarks; no functional
  difference.

### 2026-05-07: Original Approach was incomplete — supersede

The 2026-04-20 entries treated this as a `user_id`-parsing bug
solved by switching to admin-level coord fns. End-to-end tracing
revealed the same masking is also applied to `provider_user_id`
(`admin/optional.rs:187`) and `credential_id`
(`admin/optional.rs:155`), which flow through URL path parameters
into `ProviderUserId::new` / `CredentialId::new` — both of which
also reject `*`. The original fix would only have shifted the
visible error from "Invalid user ID" to "Invalid provider user
ID" / "Invalid credential ID" without fixing the underlying issue.

The deeper conflict: demo masking and admin write actions cannot
both be supported on the same per-resource items (you would need
an out-of-band cleartext side channel that defeats the masking).
Resolved by gating the two affected actions in the UI when
masking is active, and treating the existing validator rejections
as documented defense-in-depth rather than an accident.

### 2026-05-07: Scope reduced to UI gating only — defer the user_id round-trip removal

Initial draft of the rewritten Approach kept the
"switch handlers to admin-level coord fns + drop the `user_id`
body" cleanup as carried-over scope from the 2026-04-20 plan. On
review this turned out to be inherited momentum rather than
necessary work for the bug fix. The UI gating in step 1-3 is
self-sufficient.

Cross-checking what the round-trip actually does in non-demo
mode: it lets `delete_oauth2_account_core` /
`delete_passkey_credential_core` perform an
`account.user_id == posted_user_id` check before deleting. In
the normal click path this is self-referential (both values come
from the same template render), but it does fail-safe when the
two values disagree — e.g. if a future template change wires
`user_id` and the resource ID from different rows, or if the
template was rendered with stale data while ownership shifted
on the server. Marginal but non-zero defensive value.

Decision: keep the round-trip and the user-level core fn calls
for now. The cleanup remains a defensible change but no longer
load-bearing; tracked here for whoever revisits this area later.
Trade-off when the time comes:
- adopt the cleanup → pattern alignment + fresh-DB admin check
  via `validate_admin_session`
- keep current → the small fail-safe described above

## Resolution

Fixed in commit `1b5afdf` on branch
`fix-admin-demo-mode-actions-disabled`.

- Added `Masker::is_active(&self) -> bool` accessor
  (`oauth2_passkey_axum/src/admin/masking.rs`).
- Added `actions_disabled: bool` to `AdminUserPageTemplate`,
  populated from `masker.is_active()` at the single masker
  construction site (`oauth2_passkey_axum/src/admin/optional.rs`).
- Gated the Unlink (oauth2 account) and Delete (passkey
  credential) buttons in `templates/admin_user_page.j2` to render
  with `disabled` and a tooltip when `actions_disabled` is true.

The `*Id::new` validators that already reject `*` remain as the
defense-in-depth backstop if the disabled UI is ever bypassed.

Manual verification:
- `O2P_DEMO_MODE=true`, admin views another user → Unlink and
  Delete buttons rendered disabled with tooltip.
- `O2P_DEMO_MODE=true`, admin views own page → buttons enabled,
  operations succeed.
- `O2P_DEMO_MODE` unset → buttons enabled, operations succeed.

Out of scope for this fix (deferred indefinitely): switching the
two handlers to `delete_oauth2_account_admin` /
`delete_passkey_credential_admin` and removing the `user_id`
request-body round-trip. See the 2026-05-07 Decision Log entries.
