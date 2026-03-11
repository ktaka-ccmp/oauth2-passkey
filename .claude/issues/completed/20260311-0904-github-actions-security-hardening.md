# Issue: GitHub Actions Security Hardening

## Table of Contents

- [Description](#description)
- [Audit Results](#audit-results)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260311-0904

## Created: 2026-03-11-09-04

## Closed: 2026-03-11-09-33

## Status: completed

## Priority: medium

## Difficulty: small

## Description

Security audit of GitHub Actions workflows revealed several hardening opportunities.
Prompted by the "hackerbot-claw" AI-powered attack campaign (Feb 2026) that exploited
`${{ }}` direct expansion and `pull_request_target` misuse in major OSS repositories.

No Critical issues found in this repository, but three Warning-level improvements needed:
- Missing explicit `permissions` declarations (ci.yml, coverage.yml, deploy-demo.yml)
- Direct `${{ }}` expansion in `run:` steps (deploy-demo.yml)

Reference:
- https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation
- https://zenn.dev/aeyesec/articles/417578718dcced

## Audit Results

### Checks Performed

1. `${{ }}` direct expansion in `run:` steps
2. `pull_request_target` safety
3. `permissions` configuration
4. `secrets` exposure
5. `self-hosted` runner usage
6. AI review integration safety

### Pre-Fix Findings

| File | Rating | Issues |
|------|--------|--------|
| `ci.yml` | **Warning** | `permissions` not declared |
| `coverage.yml` | **Warning** | `permissions` not declared |
| `docs.yml` | **OK** | Properly configured |
| `deploy-demo.yml` | **Warning** | `permissions` not declared + `${{ }}` direct expansion in `run:` |

**No Critical issues.** Repository avoids the most dangerous patterns:
- No `pull_request_target` usage
- No external input (PR title, branch name) expanded in `run:` steps
- No `self-hosted` runners
- No AI review integrations

### ci.yml -- Warning

- **Problem**: No `permissions` declaration at workflow or job level
- **Risk**: Relies on repository default permissions; `pull_request` trigger means external PRs fire this
- **Fix**: Add `permissions: contents: read` after the `on:` block

### coverage.yml -- Warning

- **Problem**: No `permissions` declaration
- **Risk**: Same as ci.yml; `codecov/codecov-action@v4` uses `GITHUB_TOKEN` implicitly
- **Fix**: Add `permissions: contents: read` after the `on:` block

### docs.yml -- OK

- Permissions properly set: `contents: read`, `pages: write`, `id-token: write`
- Only triggers on `push` to `master` and `workflow_dispatch` (no external PR trigger)
- No `${{ }}` in `run:` steps
- Has `concurrency` to prevent duplicate deploys

### deploy-demo.yml -- Warning

- **Problem A**: No `permissions` declaration despite using `secrets.GCP_SA_KEY` and `secrets.GCP_PROJECT_ID`
- **Problem B**: `${{ }}` direct expansion in `run:` step (lines 37-44):
  - `${{ env.REGION }}` -- workflow-defined constant (low risk)
  - `${{ env.SERVICE }}` -- workflow-defined constant (low risk)
  - `${{ secrets.GCP_PROJECT_ID }}` -- secret expanded directly in shell (low practical risk since GCP project IDs are alphanumeric, but bad pattern)
- **Mitigating factor**: Only triggers on `push` to `dev`, not on external PRs
- **Fix**:
  - Add `permissions: contents: read` at workflow level
  - Move `secrets.GCP_PROJECT_ID` to `env:` block, reference as `$GCP_PROJECT_ID`
  - Reference workflow-level `env` vars as shell vars `$REGION`, `$SERVICE` instead of `${{ env.REGION }}`

### Post-Fix Verification

All 4 workflows pass with **OK** rating after fixes applied.

## Related Issues

None

## Approach

1. Add `permissions: contents: read` to ci.yml, coverage.yml, deploy-demo.yml
2. Refactor deploy-demo.yml to pass `${{ secrets.GCP_PROJECT_ID }}` through `env:` instead of direct expansion in `run:`
3. Replace `${{ env.REGION }}` and `${{ env.SERVICE }}` with shell variable references `$REGION` and `$SERVICE` in deploy-demo.yml

## Related Files

- `.github/workflows/ci.yml`
- `.github/workflows/coverage.yml`
- `.github/workflows/deploy-demo.yml`
- `.github/workflows/docs.yml` (already OK, no changes needed)

## Implementation Tasks

- [x] Add `permissions: contents: read` to ci.yml
- [x] Add `permissions: contents: read` to coverage.yml
- [x] Add `permissions: contents: read` to deploy-demo.yml
- [x] Refactor deploy-demo.yml: move `secrets.GCP_PROJECT_ID` to `env:` block
- [x] Refactor deploy-demo.yml: replace `${{ env.* }}` with shell variable references in `run:`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-11: Initial audit and issue creation

- Context: hackerbot-claw attack campaign demonstrated real-world exploitation of GitHub Actions vulnerabilities
- Decision: Audit all workflows and harden with explicit permissions and safe variable expansion
- Reason: Even though no Critical issues exist (no `pull_request_target`, no external input in `run:`), defense-in-depth best practices should be applied

## Resolution

All 5 implementation tasks completed and verified via `/audit-workflows`:
- Added `permissions: contents: read` to ci.yml, coverage.yml, deploy-demo.yml
- Refactored deploy-demo.yml to use `env:` for secrets and shell variables for workflow-level env vars
- Post-fix audit confirms all 4 workflows pass with OK rating
- GitHub Actions security policy added to global `~/.claude/CLAUDE.md` on all machines
- `/audit-workflows` custom command created globally for future re-audits
