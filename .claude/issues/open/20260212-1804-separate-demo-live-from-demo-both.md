# Issue: Separate demo-live from demo-both

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260212-1804

## Created: 2026-02-12-18-04

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Separate the live demo site (passkey-demo.ccmp.jp) from the library usage example
(demo-both). The live site will receive UI/UX customizations (issue `20260210-1935`)
that would make it unsuitable as a simple library usage example.

- `demo-both`: Preserved as a simple, clean library usage example
- `demo-live`: Live demo site at passkey-demo.ccmp.jp with deployment files and future UI customizations

## Related Issues

- `20260210-1935` Demo Site UI/UX Customizations (motivation: UI changes would diverge from example)
- `2026-01-30-08` Demo Site Deployment (completed: deployment infrastructure already in demo-both)
- `20260212-1200` GitHub Actions Auto-Deploy (affected: paths will change)
- `20260212-0235` Standalone Demo Repository (related: alternative long-term approach)

## Approach

### Branch state comparison (verified 2026-02-12)

| Branch | demo-both contents |
|--------|-------------------|
| **master** (= origin/master) | `Cargo.toml`, `README.md`, `src/`, `templates/` |
| **dev** (= origin/dev) | master + `Dockerfile`, `docker-compose.yml` |
| **dev-2026-01-30-08** (current) | dev + `DEPLOY.md`, `cloudbuild.yaml`, `env.cloud-run.yaml` |

master vs dev diff in demo-both:
- `Cargo.toml`: dev adds `bundled-tls` feature (needed for Docker/Cloud Run)
- `src/main.rs`: dev adds `PORT` env var support (needed for Cloud Run)
- `src/protected.rs`, `src/server.rs`, `templates/`: identical

### Restore source for demo-both

Use **master** (`git checkout master -- demo-both/`). Rationale:
- No deployment files (Dockerfile, docker-compose.yml, etc.)
- No `bundled-tls` feature (not needed for a simple example)
- No `PORT` env var (simple example uses hardcoded port 3001)
- `src/protected.rs`, `src/server.rs`, `templates/` are identical to dev

### Step-by-step plan

1. **Rename**: `git mv demo-both demo-live`
2. **Restore demo-both from master**: `git checkout master -- demo-both/`
3. **Update workspace `Cargo.toml`**: Add `demo-live` to members list
4. **Update `demo-live` internals**:
   - `Cargo.toml`: Change `name = "demo-both"` to `name = "demo-live"`
   - `Dockerfile`: Update paths (`demo-both/` -> `demo-live/`)
   - `cloudbuild.yaml`: Update Dockerfile path reference
   - `DEPLOY.md`: Update all `demo-both` references to `demo-live`
   - `docker-compose.yml`: Update if needed
5. **Update external references**:
   - Root `CLAUDE.md`: Update demo-both references that now refer to demo-live
   - `.dockerignore`: Check if demo-both is mentioned
   - `.gcloudignore`: Check if demo-both is mentioned
   - Issue files referencing demo-both paths
   - `docs/` files referencing demo-both
   - `Readme.md`, `oauth2_passkey_axum/README.md`
6. **Verify**:
   - `cargo build` (workspace compiles)
   - `cargo test` (all tests pass)
   - `cargo clippy --all-targets --all-features`
   - Docker build works with updated paths

### Files with `demo-both` references (37 files found)

**Must update (functional impact):**
- `Cargo.toml` (workspace members)
- `demo-live/Cargo.toml` (package name)
- `demo-live/Dockerfile` (internal paths)
- `demo-live/cloudbuild.yaml` (Dockerfile path)
- `demo-live/DEPLOY.md` (all deployment instructions)
- `demo-live/docker-compose.yml` (if any paths)
- `CLAUDE.md` (build/run commands)

**Should update (documentation accuracy):**
- `Readme.md`
- `oauth2_passkey_axum/README.md`
- `demo-cross-origin/README.md`
- `docs/src/getting-started/architecture.md`
- `docs/src/getting-started/quick-start.md`
- `docs/src/guides/tunneling.md`
- `docs/src/security/csrf.md`

**Issue files (update for consistency):**
- `.claude/issues/open/20260210-1935-demo-site-ui-customizations.md`
- `.claude/issues/open/20260212-1200-github-actions-auto-deploy.md`
- `.claude/issues/open/20260212-0235-standalone-demo-repository.md`
- `.claude/issues/completed/2026-01-30-demo-site-deployment.md`

**Skip (historical/archived, no functional impact):**
- `.claude/sessions/` files
- `.claude/issues/completed/` (other than deployment issue)
- `docs/src/archived/` files
- `.junk/` files
- `.backup/` files
- `Cargo.lock` (auto-updated by cargo)

### What stays in demo-both (restored from master)

Library usage example with no deployment files:
- `src/main.rs` - OAuth2 + Passkey setup (hardcoded port 3001, no PORT env var)
- `src/protected.rs` - Protected page handler
- `src/server.rs` - HTTP server setup
- `templates/` - Askama templates
- `Cargo.toml` - No `bundled-tls` feature
- `README.md` - Usage explanation

## Related Files

- `demo-both/` (current, to be preserved as example)
- `demo-live/` (new, for live site)
- `Cargo.toml` (workspace)
- All files listed in the approach section above

## Implementation Tasks

- [ ] `git mv demo-both demo-live`
- [ ] Restore `demo-both/` from master: `git checkout master -- demo-both/`
- [ ] Update `demo-live/Cargo.toml` package name
- [ ] Update workspace `Cargo.toml` (add demo-live)
- [ ] Update `demo-live/Dockerfile` paths
- [ ] Update `demo-live/cloudbuild.yaml` paths
- [ ] Update `demo-live/DEPLOY.md` references
- [ ] Update root `CLAUDE.md`
- [ ] Update documentation files (Readme.md, docs/, READMEs)
- [ ] Update open issue files
- [ ] Verify: `cargo build`, `cargo test`, `cargo clippy`
- [ ] Verify: Docker build with updated paths

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-12: Separate live site from library example

- Context: Issue `20260210-1935` (UI/UX Customizations) will significantly change
  the demo UI (field masking, admin selection, OAuth2-only gate). These changes
  would make demo-both unsuitable as a simple library usage example.
- Decision: Rename demo-both to demo-live for the live site, restore demo-both
  as a clean example
- Reason: Preserves demo-both as a simple, representative library usage example
  while allowing the live site to evolve independently with custom UI/UX

## Resolution
