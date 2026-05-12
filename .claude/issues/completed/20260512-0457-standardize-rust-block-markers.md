# Issue: Standardize Rust code block markers in mdBook docs to `rust,ignore`

## Metadata

- ID: 20260512-0457
- Created: 2026-05-12-04-57
- Closed: 2026-05-12-05-36
- Status: completed
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

- [x] Spot-check each plain `rust` block; confirm excerpt vs. standalone
- [x] Replace `rust` -> `rust,ignore` for confirmed excerpts
- [x] Run `mdbook build docs` (must remain clean)
- [ ] Optionally: run `mdbook test docs` (if it works) to confirm no remaining blocks try to compile and fail — skipped: `docs/book.toml` has no `[rust]` section, so `mdbook test` has no way to resolve the workspace crates and would fail across all blocks regardless of markers

### Verification

- `mdbook build docs` clean
- `grep -rn '^```rust$' docs/src/` returns no matches in the listed files (except any deliberately-runnable blocks)

## Resolution

Branch: `chore/standardize-rust-block-markers`.

**Scope correction.** The audit cited in the Problem section was too
narrow — it only searched `docs/src/security/*.md` and
`docs/src/appendix/type-safe.md`. A workspace-wide check
(`grep -rn '^```rust$' docs/src/`) revealed plain `rust` blocks
across ~26 files in total, not 5. All were processed in this commit.

**Treatment of `fn main` blocks.** Four files contained blocks
with `fn main` that could in principle be standalone:

- `docs/src/api/axum.md` (Quick Start + Protected API Routes example)
- `docs/src/api/core.md` (init example)
- `docs/src/archived/design-proposals/TestKeyPairGeneration.md`
  (one-time key generation program)
- `docs/src/integration/passkey.md` (Demo Application snippet)

These were also marked `rust,ignore`. Rationale: `docs/book.toml`
has no `[rust]` section configured for `mdbook test`, so even
these `fn main` blocks have no path to the workspace crates and
would not compile under `mdbook test` as-is. Marking them
`rust,ignore` matches reality. If `mdbook test` is added to CI
later with proper crate linking, individual blocks can be
promoted back to plain `rust` after verifying they actually
compile.

**Final state.**

- All 26 files modified: every plain ` ```rust ` block now
  carries `,ignore` (43 files total carry `rust,ignore` after
  this commit, including those already converted in prior
  branches).
- `grep -rn '^```rust$' docs/src/` returns zero matches.
- `mdbook build docs` clean.

Files touched:

- `docs/src/api/axum.md`
- `docs/src/api/core.md`
- `docs/src/appendix/security-advisories.md`
- `docs/src/appendix/terminology.md`
- `docs/src/appendix/type-safe.md`
- `docs/src/archived/TestStrategy.md`
- `docs/src/archived/ToDo.md`
- `docs/src/archived/design-proposals/TestKeyPairGeneration.md`
- `docs/src/archived/design-proposals/bearer-token-support.md`
- `docs/src/archived/design-proposals/cache-expiration-system-simplification.md`
- `docs/src/archived/design-proposals/implementing-tracing.md`
- `docs/src/archived/design-proposals/integration-testing-plan.md`
- `docs/src/archived/design-proposals/oauth2-account-linking-api-simplification.md`
- `docs/src/archived/design-proposals/type-safe-validation.md`
- `docs/src/archived/testing-assessments/FINAL_TEST_QUALITY_ANALYSIS.md`
- `docs/src/archived/testing-assessments/OAuth2TestAssessment.md`
- `docs/src/archived/testing-assessments/OAuth2TestCleanupCompletion.md`
- `docs/src/archived/testing-assessments/PasskeyTestInsight.md`
- `docs/src/archived/testing-assessments/UnitTestInsight.md`
- `docs/src/archived/testing-assessments/assessment_202506/OAuth2PasskeyAxumTestQualityAssessment.md`
- `docs/src/integration/deployment-patterns.md`
- `docs/src/integration/oauth2.md`
- `docs/src/integration/passkey.md`
- `docs/src/maintainer/development.md`
- `docs/src/security/authorization.md`
- `docs/src/security/csrf.md`
- `docs/src/security/passkey-registration-protection.md`
- `docs/src/security/session.md`
- `docs/src/webauthn/aaguid-metadata.md`
- `docs/src/webauthn/tpm.md`
- `docs/src/webauthn/user-handle-and-signal-api.md`
