# Issue: Periodic Dependency Updates and Security Audit

## Metadata

- ID: 20261123-2151
- Created: 2026-11-23-21-51
- Closed:
- Status: open
- Priority: medium
- Difficulty: small
- Related Issues:
  - `20261123-2153` Upgrade tower-http to 0.7 (a pending incompatible upgrade)

## Problem

Dependency updates happen only when CI starts failing.

In November 2026 the `Security Audit` job in `ci.yml` failed on 11
RustSec advisories that had accumulated in `Cargo.lock`. Clearing them
needed sqlx 0.8 -> 0.9, jsonwebtoken 10 -> 12 and an MSRV bump to 1.94
(PR #356). While that PR was open, another advisory (RUSTSEC-2026-0594,
`cookie`) was published and failed the audit again.

Current state (checked on 2026-11-23):

- No `.github/dependabot.yml` or Renovate configuration exists.
- `cargo audit` runs only in `ci.yml`, i.e. on pushes and PRs to
  `master`/`dev`. A new advisory is noticed only when the next PR runs.
- `ci-nightly.yml` runs weekly (Monday 06:00 UTC) on beta/nightly, but
  does not run `cargo audit`.
- Released crates are not rebuilt, so users only get the minimum
  versions declared in `Cargo.toml` raised when a new version is
  released.

## Timeline

## Latest Plan

1. Add `cargo audit` to the weekly `ci-nightly.yml` run, so new
   advisories are noticed without waiting for a PR.
2. Add Dependabot (or Renovate) for Cargo and GitHub Actions, targeting
   `dev`, with grouped updates to keep the PR count low.
3. Decide a cadence for patch releases that only update dependencies
   (for example, when an advisory affects a declared minimum version).

### Files

- `.github/workflows/ci-nightly.yml`
- `.github/dependabot.yml` (new) or `renovate.json` (new)
- `docs/src/maintainer/ci-cd.md`

### Implementation Tasks

- [ ] Add a `cargo audit` job to `ci-nightly.yml` (explicit
      `permissions: contents: read`)
- [ ] Choose Dependabot or Renovate and add its configuration
- [ ] Document the update and release policy in `ci-cd.md`
- [ ] Run `/audit-workflows` after the workflow changes

### Verification

- The weekly run executes `cargo audit` (check with `workflow_dispatch`
  if available, or the next scheduled run).
- The update bot opens a PR against `dev`.

## Resolution
