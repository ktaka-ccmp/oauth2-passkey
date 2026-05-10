# Issue: validate_origin `starts_with` allows subdomain confusion via Referer

## Table of Contents

- [Description](#description)
- [Reproduction](#reproduction)
- [Proposed Fix](#proposed-fix)
- [Related Files](#related-files)
- [Timeline](#timeline)

## ID: 20260511-0543

## Created: 2026-05-11-05-43

## Status: open

## Priority: medium

## Difficulty: low

## Description

`validate_origin` in `oauth2_passkey/src/oauth2/main/utils.rs:129-134`
uses a raw `starts_with` to compare the incoming Origin/Referer header
against `expected_origin` and against each entry in
`additional_allowed_origins`. The expected value has no trailing
delimiter (it is built as `"{scheme}://{host}[:{port}]"`), so any
candidate that begins with the expected string but has additional
arbitrary characters in the host segment will satisfy the check.

For `expected_origin = "https://accounts.google.com"`, a `Referer` of
`https://accounts.google.com.attacker.com/path` passes the check
because `.` is a valid host-segment character — the prefix match does
not anchor on a host-segment boundary.

The same pattern now applies to `additional_allowed_origins`, which
the v0.6.0 preset system uses to register IdP-specific extras (e.g.
`https://login.live.com` for the Entra personal-accounts flow). The
attack surface widens with every additional allowed origin.

Surfaced by code review of PR #295 (v0.6.0 release).

### Real-world reachability

Constrained. An attacker needs the browser to send a Referer whose
host starts with the allowed origin and continues with attacker-
controlled characters. That requires one of:

- DNS takeover of a name that subsumes the legitimate origin
- An open-redirect chain at the IdP host that sets the Referer
- An attacker-controlled subdomain when the allowed origin is itself
  a subdomain prefix (less likely in the OAuth2 callback flow)

The `Origin` header path (preferred over `Referer`) is unaffected in
practice because browsers send exact origins with no path, but the
fallback `Referer` path is reachable.

This is a defense-in-depth hardening, not a known active vulnerability.

## Reproduction

Conceptual — set `expected_origin = "https://accounts.google.com"` and
call `validate_origin` with a `Referer` header of
`https://accounts.google.com.attacker.com/path`. Current code returns
`Ok(())`.

## Proposed Fix

Anchor the prefix match on a host-segment boundary. Two equivalent
approaches:

### Option A — parse and compare structurally

Parse the candidate as a URL and compare `scheme + host + port`
exactly against `expected_origin` (and each `additional_allowed_origin`).
Requires pulling `url` crate (already a transitive dep) or doing a
manual split on the first `/` after `scheme://`.

### Option B — byte-after-prefix check

After `starts_with(allowed)` returns true, verify that the candidate
byte at position `allowed.len()` is one of `/`, `?`, `#`, or that the
prefix is the entire candidate. This is a minimal patch and avoids
adding parser dependencies.

```rust
let matches = |candidate: &str| {
    let allowed_prefixes = std::iter::once(expected_origin.as_str())
        .chain(additional_allowed_origins.iter().map(|s| s.as_str()));
    allowed_prefixes.any(|allowed| {
        if !candidate.starts_with(allowed) {
            return false;
        }
        match candidate.as_bytes().get(allowed.len()) {
            None | Some(b'/') | Some(b'?') | Some(b'#') => true,
            _ => false,
        }
    })
};
```

Option B is recommended — smaller surface change, no new dependency,
straightforward to test.

## Related Files

### To modify

- `oauth2_passkey/src/oauth2/main/utils.rs` — `validate_origin` body
- `oauth2_passkey/src/oauth2/main/utils/tests.rs` — add negative tests:
  - `https://accounts.google.com.attacker.com/path` rejected
  - `https://login.live.com.attacker.example` rejected
  - `https://accounts.google.com/path?query=...` still accepted
  - `https://accounts.google.com:443` correctness if port encoded

## Timeline

<!-- APPEND-ONLY: Add new entries at the bottom. -->

### 2026-05-11: Filed during v0.6.0 release review

- Surfaced by code review of PR #295 (review-295.txt § Findings worth
  fixing item 1). Reviewer's recommendation: pre-tag fix or follow-up.
- Decision: defer to follow-up (file issue, do not block v0.6.0). The
  v0.6.0 release prep is doc-accuracy fixes only; this is a code change
  that warrants its own PR with negative tests.
- Reference: review-295.txt § "Findings worth fixing" item 1
