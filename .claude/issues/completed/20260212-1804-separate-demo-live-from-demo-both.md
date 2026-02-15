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

## Closed: 2026-02-12

## Status: completed

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

### Branch state comparison (verified 2026-02-12, updated after PR #205 merge)

| Branch | demo-both contents |
|--------|-------------------|
| **master** | `Cargo.toml`, `README.md`, `src/`, `templates/` |
| **dev** | master + `Dockerfile`, `docker-compose.yml`, `DEPLOY.md`, `DOCKER_NOTES.md`, `cloudbuild.yaml`, `env.cloud-run.yaml` |
| **dev-20260212-1804** (current, from dev) | same as dev (working branch for this issue) |

master vs dev diff in demo-both:
- `Cargo.toml`: dev adds `bundled-tls` feature (needed for Docker/Cloud Run)
- `src/main.rs`: dev adds `PORT` env var support (needed for Cloud Run)
- `src/protected.rs`, `src/server.rs`, `templates/`: identical
- dev adds deployment files: `Dockerfile`, `docker-compose.yml`, `DEPLOY.md`, `DOCKER_NOTES.md`, `cloudbuild.yaml`, `env.cloud-run.yaml`

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
   - `DOCKER_NOTES.md`: Update TLS feature chain and file references
   - `docker-compose.yml`: Update paths in comments and dockerfile reference
   - `env.cloud-run.yaml`: Update comments
5. **Update issue files** (deployment/live-site references -> demo-live):
   - `20260210-1935`: UI customization target changes to demo-live
   - `20260212-1200`: Deployment paths change to demo-live
   - `20260212-0235`: Extraction source changes to demo-live
6. **Optionally add demo-live** to `CLAUDE.md` and `Readme.md` (new entries, not updates)
   - Note: Existing `demo-both` references in docs/READMEs stay as-is (library example)
7. **Verify**:
   - `cargo build` (workspace compiles)
   - `cargo test` (all tests pass)
   - `cargo clippy --all-targets --all-features`
   - Docker build works with updated paths

### Files with `demo-both` references (40 files found)

**Must update (demo-live internals, paths change from demo-both/ to demo-live/):**
- `Cargo.toml` (workspace members: add demo-live)
- `demo-live/Cargo.toml` (package name)
- `demo-live/Dockerfile` (internal paths)
- `demo-live/cloudbuild.yaml` (Dockerfile path)
- `demo-live/DEPLOY.md` (all deployment instructions)
- `demo-live/DOCKER_NOTES.md` (TLS feature chain, file references)
- `demo-live/docker-compose.yml` (paths in comments and dockerfile reference)
- `demo-live/env.cloud-run.yaml` (comments)

**Issue files (deployment/live-site references -> demo-live):**
- `.claude/issues/open/20260210-1935-demo-site-ui-customizations.md`
- `.claude/issues/open/20260212-1200-github-actions-auto-deploy.md`
- `.claude/issues/open/20260212-0235-standalone-demo-repository.md`

**No change needed (refer to demo-both as library usage example, which stays demo-both):**
- `CLAUDE.md`, `Readme.md`, `oauth2_passkey_axum/README.md`, `oauth2_passkey_axum/src/lib.rs`
- `demo-cross-origin/README.md`
- `docs/src/getting-started/architecture.md`, `docs/src/getting-started/quick-start.md`
- `docs/src/guides/tunneling.md`, `docs/src/security/csrf.md`
- `.dockerignore`, `.gcloudignore` (no demo-both references)

**Skip (historical/archived):**
- `.claude/sessions/`, `.claude/issues/completed/`, `docs/src/archived/`
- `docs/reorganization-plan.md`, `TestStrategy.md`, `.junk/`, `.backup/`
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

- [x] `git mv demo-both demo-live`
- [x] Restore `demo-both/` from master: `git checkout master -- demo-both/`
- [x] Update `demo-live/Cargo.toml` package name
- [x] Update workspace `Cargo.toml` (add demo-live)
- [x] Update `demo-live/Dockerfile` paths
- [x] Update `demo-live/cloudbuild.yaml` paths
- [x] Update `demo-live/DEPLOY.md` references
- [x] Update `demo-live/DOCKER_NOTES.md` references
- [x] Update `demo-live/docker-compose.yml` references
- [x] Update `demo-live/env.cloud-run.yaml` references
- [x] Update issue files (20260210-1935, 20260212-1200, 20260212-0235)
- [x] Skipped: demo-live entries in `CLAUDE.md` and `Readme.md` (not needed)
- [x] Verify: `cargo build`, `cargo test`, `cargo clippy`
- [x] Verify: Docker build with updated paths

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

### 2026-02-12: Updated branch comparison and file lists after PR #205 merge

- Context: All changes from dev-2026-01-30-08 were merged into dev via PR #205.
  The branch comparison table was outdated (still referenced dev-2026-01-30-08).
- Decision: Updated table to reflect current state (dev now has all deployment
  files), working branch is dev-20260212-1804. Added missing files to update
  lists (DOCKER_NOTES.md, env.cloud-run.yaml, lib.rs doc comment, issues README).
- Reason: Accuracy before implementation

### 2026-02-12: Corrected external reference update scope

- Context: Initial plan listed all files referencing `demo-both` as needing updates,
  but after separation both `demo-both` and `demo-live` coexist. External files
  (CLAUDE.md, Readme.md, docs/, READMEs, lib.rs) reference `demo-both` as the
  library usage example, which remains `demo-both`.
- Decision: Only update demo-live internals and issue files where references are
  about deployment/live-site (which moves to demo-live). External docs stay as-is.
- Reason: demo-both continues to exist as the library example; changing its references
  would be incorrect

## Resolution

Separated `demo-live` from `demo-both` successfully:

- **demo-both**: Restored from master as a clean library usage example (no deployment files)
- **demo-live**: Live demo site with all deployment files (Dockerfile, docker-compose.yml, cloudbuild.yaml, DEPLOY.md, etc.)
- Updated all internal paths and references in demo-live
- Updated 3 issue files (20260210-1935, 20260212-1200, 20260212-0235) for deployment/live-site references
- External docs referencing demo-both as library example left unchanged (correct as-is)
- Verified: cargo build, cargo test, cargo clippy, Docker build all pass
- Committed as `1bfd461`
- Cloud Run (passkey-demo.ccmp.jp) unaffected; next redeployment uses `demo-live/cloudbuild.yaml`
