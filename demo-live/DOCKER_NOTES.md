# Docker Design Notes

Design decisions, trade-offs, and troubleshooting notes for the Docker image
used in this demo application. For deployment steps, see [DEPLOY.md](DEPLOY.md).

## Base Image Selection

| Base Image | Size | Notes |
|------------|------|-------|
| `scratch` (selected) | 0 MB | Empty image. Requires fully static binary (musl). No shell, no libc. |
| `alpine` | ~8 MB | musl libc. Some crates have build issues. |
| `distroless` | ~20 MB | Google's minimal image. No shell, hard to debug. |
| `bookworm-slim` | ~75 MB | glibc. Best compatibility. |

## Image Size

| Component | Before (bookworm-slim) | After (scratch) |
|-----------|----------------------|-----------------|
| Base image | 74.8 MB | 0 MB |
| ca-certificates | 9.2 MB | 0 MB (bundled) |
| Binary | 27.1 MB (glibc) | 27.7 MB (musl) |
| **Total** | **111 MB** | **27.7 MB** |

## Challenges with `scratch` and Resolutions

| Challenge | Impact | Resolution |
|-----------|--------|------------|
| No ca-certificates | OAuth2 (Google) TLS connections fail | `webpki-roots`: Mozilla certs bundled at compile time |
| No libc | musl cross-compilation needed; C deps (libsqlite3-sys, aws-lc-sys) complex | `rust:1.88-alpine` builder with `musl-dev cmake make perl` |
| No shell | `docker exec` debugging impossible | Accepted: `docker logs` still works; Cloud Run has no `docker exec` anyway |
| No DNS libraries | Name resolution may fail | Rust's async DNS resolver works without system libraries |
| `reqwest::get()` ignores bundled certs | HTTPS fails with `add_parsable_certificates processed 0 valid and 0 invalid certs` | All call sites replaced with shared `get_client()` using `use_preconfigured_tls()` |

### Shell-less container trade-offs

| Operation | With shell | scratch (no shell) |
|-----------|-----------|---------------------|
| `docker exec -it <c> sh` | OK | Impossible |
| File system inspection (`ls`, `cat`) | OK | Impossible |
| Network diagnostics (`curl`, `ping`) | OK | Impossible |
| Environment variables (`env`) | OK | Impossible |
| Log viewing (`docker logs`) | **OK** | **OK** |

`docker logs` reads stdout/stderr from outside the container, so no shell is needed.
For Cloud Run, `docker exec` is not available anyway (containers are fully managed),
so the shell-less trade-off has zero practical impact.

## TLS Architecture

The `bundled-tls` feature flag controls whether `webpki-roots` and `rustls` are included:

```
demo-live (bundled-tls) -> oauth2-passkey-axum (bundled-tls) -> oauth2-passkey (bundled-tls)
```

In `oauth2_passkey/src/utils.rs`, `get_client()` conditionally uses `use_preconfigured_tls()`:
- With `bundled-tls`: Uses compiled-in Mozilla root certificates (for scratch/minimal containers)
- Without `bundled-tls`: Uses system certificate store (for normal deployments)

Note: reqwest 0.13 removed the `rustls-tls-webpki-roots` feature flag.
Code-level `use_preconfigured_tls()` API is required instead.

### Removed unnecessary `ring` feature from `rustls`

The `ring` crypto provider for rustls was enabled but never used.
Transitive deps (reqwest -> hyper-rustls) use `aws-lc-rs` (default) instead.
The direct `ring` crate (for WebAuthn) is unaffected.

## Binary Size Optimization (not applied)

| Method | Effect | Trade-off |
|--------|--------|-----------|
| `strip = true` | 27 MB -> 22 MB | Loses debug symbols |
| `lto = true` | Further reduction | Longer build time |
| `opt-level = "z"` | Optimize for size | Slower runtime |
| `codegen-units = 1` | Better optimization | Longer build time |

Not applied because 27.7 MB is already acceptable for Cloud Run.

## Local Testing Notes

### docker-compose.yml environment handling

The `docker-compose.yml` uses two mechanisms for environment variables:

1. **`env_file: ../.env`** - Reads the repository root `.env` file (OAuth2 credentials, etc.)
2. **`environment:`** - Overrides container-specific values:

```yaml
environment:
  PORT: 8080
  ORIGIN: "http://localhost:3001"
  GENERIC_DATA_STORE_TYPE: sqlite
  GENERIC_DATA_STORE_URL: "sqlite:file:memdb1?mode=memory&cache=shared"
  GENERIC_CACHE_STORE_TYPE: memory
  GENERIC_CACHE_STORE_URL: "unused"
```

### Docker `--env-file` quoting problem

Docker `--env-file` does NOT strip quotes from values (unlike `dotenvy`).
For example, `OAUTH2_RESPONSE_MODE='query'` in `.env` would be parsed as
literal `'query'` (with quotes), causing a panic. Docker Compose's `env_file:`
directive handles quotes correctly, which is why `docker-compose.yml` is used
instead of `docker run --env-file`.

### BuildKit cache invalidation

After relocating Dockerfile (e.g., root -> `demo-live/`), BuildKit's
content-based cache may not invalidate properly. Symptom: all build steps
show `CACHED` despite source code changes.

Fix: `docker compose build --no-cache` (forces full rebuild, ~7min for Rust).
Normal workflow: `--build` is sufficient; use `--no-cache` only when behavior
is suspicious.

## In-Memory Backend Stability

### JWKS cache deadlock (fixed in commit `66ab51f`)

OAuth2 login deadlocks exactly 10 minutes after first login when using
`GENERIC_CACHE_STORE_TYPE=memory`. The `fetch_jwks_cache()` function holds
a `tokio::sync::Mutex` guard via `if let` temporary lifetime, then tries to
re-acquire the same non-reentrant Mutex inside the body -> deadlock.

Root cause: `if let Some(x) = MUTEX.lock().await.get().await { MUTEX.lock().await.remove()... }`
The MutexGuard temporary from the scrutinee lives through the entire `if let` body.

Why only in-memory: Redis auto-expires entries via TTL, so the expired-entry code
path (which triggers re-locking) is never reached. In-memory cache originally ignored
TTL, so entries persisted forever and the expired path was always triggered after 600s.

Fixes:
1. Refactored `fetch_jwks_cache()` to use `cache_operations` module functions
   (each acquires and releases the lock independently)
2. Added lazy TTL expiration to `InMemoryCacheStore` (defense in depth)

### SQLite in-memory tables disappearing (fixed in commits `8b7839d`, `0129ed6`)

Tables created at startup vanished after ~30 minutes of low traffic.

Root cause: `SqlitePool::connect_lazy_with(opts)` defaults to `min_connections=0`.
After idle timeout (~10min) or max lifetime (~30min), all pool connections are evicted.
For in-memory databases, closing all connections destroys the database entirely.

`min_connections(1)` alone was insufficient: sqlx's default `max_lifetime` (30min)
forcibly closes connections, and during the close-then-recreate cycle, all connections
can momentarily reach 0.

Fix: `SqlitePoolOptions::new().min_connections(1).idle_timeout(None).max_lifetime(None)`
In-memory databases have no reason to cycle connections.

## Code Changes Summary

### Files modified for Docker support

- `oauth2_passkey/src/utils.rs` - `get_client()` with cfg-gated bundled TLS
- `oauth2_passkey/Cargo.toml` - `bundled-tls` feature, optional deps
- `oauth2_passkey_axum/Cargo.toml` - `bundled-tls` feature forwarding
- `demo-live/Cargo.toml` - `bundled-tls` feature forwarding
- `demo-live/src/main.rs` - PORT env var support
- `oauth2_passkey/src/oauth2/main/google.rs` - use `crate::utils::get_client`
- `oauth2_passkey/src/oauth2/discovery.rs` - use `crate::utils::get_client()`
- `oauth2_passkey/src/oauth2/main/idtoken.rs` - deadlock fix via `cache_operations`
- `oauth2_passkey/src/passkey/main/aaguid.rs` - use `crate::utils::get_client()`
- `oauth2_passkey/src/storage/cache_store/memory.rs` - lazy TTL expiration
- `oauth2_passkey/src/storage/data_store/config.rs` - in-memory SQLite pool fix
