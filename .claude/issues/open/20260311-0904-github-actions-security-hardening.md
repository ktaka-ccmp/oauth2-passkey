# Issue: GitHub Actions Security Hardening

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260311-0904

## Created: 2026-03-11-09-04

## Closed:

## Status: open

## Priority: medium

## Difficulty: small

## Description

Security audit of GitHub Actions workflows revealed several hardening opportunities.
Prompted by the "hackerbot-claw" AI-powered attack campaign (Feb 2026) that exploited
`${{ }}` direct expansion and `pull_request_target` misuse in major OSS repositories.

No Critical issues found in this repository, but three Warning-level improvements needed:
- Missing explicit `permissions` declarations (ci.yml, coverage.yml, deploy-demo.yml)
- Direct `${{ }}` expansion in `run:` steps (deploy-demo.yml)

Full audit results recorded in `.claude/sessions/2026-03-04-github-actions-security-audit.md`.

Reference:
- https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation
- https://zenn.dev/aeyesec/articles/417578718dcced

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

- [ ] Add `permissions: contents: read` to ci.yml
- [ ] Add `permissions: contents: read` to coverage.yml
- [ ] Add `permissions: contents: read` to deploy-demo.yml
- [ ] Refactor deploy-demo.yml: move `secrets.GCP_PROJECT_ID` to `env:` block
- [ ] Refactor deploy-demo.yml: replace `${{ env.* }}` with shell variable references in `run:`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-11: Initial audit and issue creation

- Context: hackerbot-claw attack campaign demonstrated real-world exploitation of GitHub Actions vulnerabilities
- Decision: Audit all workflows and harden with explicit permissions and safe variable expansion
- Reason: Even though no Critical issues exist (no `pull_request_target`, no external input in `run:`), defense-in-depth best practices should be applied

## Resolution
