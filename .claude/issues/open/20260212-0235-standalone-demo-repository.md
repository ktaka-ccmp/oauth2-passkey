# Issue: Standalone Demo Repository

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260212-0235

## Created: 2026-02-12-02-35

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Extract `demo-both` into an independent repository that uses crates.io published
dependencies (`oauth2-passkey`, `oauth2-passkey-axum`) instead of workspace path
dependencies. This would:

1. Consolidate all deployment files into a single self-contained project
   (Dockerfile, .dockerignore, .gcloudignore, cloudbuild.yaml, docker-compose.yml,
   env.cloud-run.yaml, DEPLOY.md)
2. Serve as a reference implementation for library users
3. Validate that the crates.io published versions work correctly for real deployments
4. Simplify the build context (repository root = project root)

Currently, `.dockerignore` and `.gcloudignore` must live at the repository root because
the Docker/Cloud Build context spans the entire Cargo workspace. A standalone repository
eliminates this constraint.

## Related Issues

- `2026-01-30-08` Demo Site Deployment (Cloud Run) (related to: deployment infrastructure)

## Approach

### Repository Structure

```
oauth2-passkey-demo/
  Cargo.toml              # standalone, depends on crates.io packages
  Cargo.lock
  src/main.rs
  Dockerfile
  .dockerignore
  .gcloudignore
  cloudbuild.yaml
  docker-compose.yml
  env.cloud-run.yaml
  dot.env.example
  DEPLOY.md
  README.md
```

### Key Changes from Current demo-both

- `Cargo.toml`: Replace `path = "../oauth2_passkey_axum"` with
  `oauth2-passkey-axum = { version = "0.2.x", features = ["bundled-tls"] }`
- `Dockerfile`: Simplify paths (no `demo-both/` prefix, build context = `.`)
- `.dockerignore` / `.gcloudignore`: Move from parent repo root to project root
- `cloudbuild.yaml`: Simplify (Dockerfile at `.`, not `demo-both/Dockerfile`)

### Trade-offs

| Aspect | Workspace member (current) | Standalone repository |
|--------|---------------------------|----------------------|
| Deployment files | Split across root and demo-both/ | All in one place |
| Library changes | Immediately available via path deps | Requires crates.io publish first |
| Dev iteration | Fast (local workspace) | Needs `[patch]` for local testing |
| Reference value | Low (workspace-specific setup) | High (shows real library usage) |

## Related Files

- `demo-both/` - Current workspace member to be extracted
- `demo-both/Dockerfile` - Needs path simplification
- `demo-both/docker-compose.yml` - Needs context/path updates
- `demo-both/cloudbuild.yaml` - Needs path simplification
- `demo-both/env.cloud-run.yaml` - Can be copied as-is
- `demo-both/DEPLOY.md` - Needs path updates
- `.dockerignore` - Move into standalone repo
- `.gcloudignore` - Move into standalone repo

## Implementation Tasks

- [ ] Create new GitHub repository (e.g., `oauth2-passkey-demo`)
- [ ] Copy and adapt `demo-both/src/main.rs`
- [ ] Create standalone `Cargo.toml` with crates.io dependencies
- [ ] Adapt Dockerfile (remove `demo-both/` path prefix)
- [ ] Adapt cloudbuild.yaml (remove `demo-both/` path prefix)
- [ ] Adapt docker-compose.yml (context = `.`, remove `../` references)
- [ ] Copy `.dockerignore` and `.gcloudignore` (adapt paths)
- [ ] Copy and adapt `env.cloud-run.yaml` and `DEPLOY.md`
- [ ] Create `dot.env.example` and `README.md`
- [ ] Verify local Docker build works
- [ ] Verify Cloud Run deployment works
- [ ] Decide whether to keep or remove `demo-both/` from the main workspace

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-12: Issue created

- Context: `demo-both` deployment files are split between the repository root
  (`.dockerignore`, `.gcloudignore`) and `demo-both/` due to Docker build context
  constraints. The user asked whether everything could be consolidated in one place.
- Decision: Create a standalone demo repository as a future task
- Reason: A standalone repo using crates.io dependencies would consolidate all files,
  serve as a reference implementation, and validate published library versions.
  The main workspace's `demo-both/` remains useful for development iteration.

## Resolution
