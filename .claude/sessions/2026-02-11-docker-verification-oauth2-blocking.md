# Session Snapshot: Docker Verification & OAuth2 Blocking Issue

## Date: 2026-02-11

## Current Task

Docker image verification for demo-both deployment (issue 2026-01-30-08).
Discovered OAuth2 callback blocking issue during testing.

## What Happened

### 1. Docker Build Cache Issue (resolved)
- `docker compose up --build` showed all steps `CACHED` despite code changes
- Root cause: Dockerfile relocation (root -> `demo-both/`) caused BuildKit cache mismatch
- Fix: `docker compose build --no-cache` forced full rebuild
- After rebuild: container started correctly (31 bundled + 316 remote AAGUID mappings)
- Added rebuild/cache-clear instructions to `demo-both/docker-compose.yml` comments
- Recorded in MEMORY.md for future reference

### 2. OAuth2 Callback Blocking Issue (open - needs fix)
- **Symptom**: OAuth2 popup doesn't close, server log shows "Processing OAuth2 authorization core logic" then hangs
- **Impact**: While one request is stuck, ALL other OAuth2 logins are blocked (can't even redirect to Google)
- **Root cause analysis**: Global `Mutex<Box<dyn CacheStore>>` serializes all cache operations.
  OAuth2 callback makes up to 4 external HTTP requests to Google (token exchange, OIDC discovery,
  JWKS fetch, userinfo). When any of these is slow, the Mutex contention blocks all other
  cache-dependent operations (CSRF store, nonce store, session management).
- **Proposed quick fixes**:
  1. Reduce HTTP timeout (30s -> 5s)
  2. Pre-warm OIDC Discovery and JWKS at startup
- **Deeper fix needed**: Replace single global Mutex with RwLock or per-prefix locks

## Files Modified

- `demo-both/docker-compose.yml` - Updated usage comments (rebuild vs cache-clear instructions)
- `~/.claude/projects/.../memory/MEMORY.md` - Added Docker BuildKit cache lesson

## Commits

- `6b98ca5` docs(docker): add rebuild and cache-clear instructions to docker-compose.yml

## Key Decisions

- Docker build cache issue was operational (not code bug) - documented in MEMORY.md and docker-compose.yml
- OAuth2 blocking issue identified but NOT yet fixed - user was deciding on approach

## Next Steps

### Immediate (OAuth2 blocking fix)
- [ ] Reduce `get_client()` timeout from 30s to 5s
- [ ] Add OIDC Discovery + JWKS pre-warm at startup (alongside AAGUID loading)
- [ ] Test Docker container with fix

### Deployment (issue 2026-01-30-08)
- [ ] Set up GCP project and enable Cloud Run
- [ ] Configure secrets in Google Secret Manager
- [ ] Configure Google OAuth2 redirect URIs for run.app domain
- [ ] Deploy manually and verify functionality
- [ ] Create GitHub Actions workflow for auto-deploy

### Longer-term architecture
- [ ] Replace global cache Mutex with RwLock or per-prefix locks
- [ ] Consider background JWKS refresh instead of lazy loading

## Context

- Branch: `dev-2026-01-30-08`
- The OAuth2 blocking is NOT Docker-specific - it can happen anywhere with network latency
- Root `docker-compose.yml` exists as untracked file (was unstaged from commit, kept for legacy use)
- The `aaguid.rs` remote fetch is currently fatal (user rejected making it best-effort without discussion)
