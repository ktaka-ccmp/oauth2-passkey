# Issue: Standardize Rust code block markers in mdBook docs to `rust,ignore`

## Metadata

- ID: 20260512-0457
- Created: 2026-05-12-04-57
- Closed:
- Status: open
- Priority: low
- Difficulty: small
- Related Issues:
  - `20260226-2018` Simplify OAuth2 Account Linking API (parent — surfaced during the docs restructure under that issue's Always section)

## Problem

mdBook code blocks marked ` ```rust ` are picked up by `mdbook test`
as doctests. The project convention used in most subdirectories is
` ```rust,ignore ` for excerpt code that does not compile
standalone (references types/functions not declared in scope, etc.):

- `docs/src/integration/` — uniformly `rust,ignore` (csrf-handling,
  framework, multi-origin, route-protection, server-setup,
  templates, customizing-templates, customizing-css, user-data)
- `docs/src/maintainer/development.md` — `rust,ignore`
- `docs/src/getting-started/architecture.md` — `rust,ignore`
- `docs/src/appendix/storage-pattern.md` — `rust,ignore`

Several other docs still use plain ` ```rust `, inconsistent with
this convention:

| File | Plain `rust` blocks |
|---|---|
| `docs/src/security/csrf.md` | 3 (L22, L117, L134) |
| `docs/src/security/session.md` | 1 (L147) |
| `docs/src/security/authorization.md` | 4 (L37, L69, L107, L160) |
| `docs/src/security/passkey-registration-protection.md` | 2 (L79, L100) |
| `docs/src/appendix/type-safe.md` | 19 (L7 onward) |

Total: 29 blocks across 5 files.

`mdbook test` is not currently part of CI, so these don't fail
today. The inconsistency matters because (a) it confuses future
contributors about the convention, and (b) it would silently break
if `mdbook test` is added to CI later.

## Timeline

### 2026-05-12T04:57 — Issue created during oauth2-linking-protection.md restructure

Surfaced while marking the 6 Rust blocks in
`docs/src/security/oauth2-linking-protection.md` as `rust,ignore`
under issue `20260226-2018`. Audit of sibling docs revealed the
inconsistency listed above.

## Latest Plan

Replace ` ```rust ` with ` ```rust,ignore ` for the 29 blocks
listed in Problem.

Before flipping, briefly verify each block is in fact an
excerpt (not a standalone compileable example). If any block IS
standalone-runnable, leave it as `rust` (those should remain
testable). Expected outcome: all listed blocks are excerpts, so
all get `,ignore`.

### Files

- `docs/src/security/csrf.md`
- `docs/src/security/session.md`
- `docs/src/security/authorization.md`
- `docs/src/security/passkey-registration-protection.md`
- `docs/src/appendix/type-safe.md`

### Implementation Tasks

- [ ] Spot-check each plain `rust` block; confirm excerpt vs. standalone
- [ ] Replace `rust` -> `rust,ignore` for confirmed excerpts
- [ ] Run `mdbook build docs` (must remain clean)
- [ ] Optionally: run `mdbook test docs` (if it works) to confirm no remaining blocks try to compile and fail

### Verification

- `mdbook build docs` clean
- `grep -rn '^```rust$' docs/src/` returns no matches in the listed files (except any deliberately-runnable blocks)

## Resolution
