# Issue: Demo Site Deployment (Cloud Run)

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-01-30-08

## Created: 2026-01-30

## Closed: 2026-02-12-12-00

## Status: completed

## Priority: low

## Difficulty: medium

## Description

Deploy demo applications to a public hosting platform for demonstration and testing purposes.

## Related Issues

- None

## Approach

### Platform: Google Cloud Run

| Platform | Free Tier | Always-On | DB/Cache | Code Changes |
|----------|-----------|-----------|----------|-------------|
| **Cloud Run** (selected) | 180k vCPU-sec, 2M req/mo | Yes (min-instances=1) | SQLite (ephemeral) + memory cache | None |
| Oracle Cloud | ARM 4CPU/24GB (permanent) | Yes | Self-managed (persistent) | None |
| Fly.io | None | N/A | N/A | None |
| Render | 750 hrs/mo | No (sleeps 15min) | DB expires 30 days | None |
| Railway | $5 credit/mo | Yes | Usage-based | None |

### Docker Image

Multi-stage build with `scratch` base image (27.7MB total):

- **Builder**: `rust:1.88-alpine` (musl libc for static linking)
- **Runtime**: `scratch` (no OS, no shell, just the binary)
- **TLS certificates**: Bundled at compile time via `webpki-roots` (no `ca-certificates` needed)
- **PORT**: Configurable via environment variable (Cloud Run sets `PORT=8080`)

### Storage Strategy

- **SQLite** (ephemeral): Data is lost on container restart, acceptable for demo
- **Memory cache**: No Redis needed, simplifies deployment
- Users can re-register passkeys as needed

### Deployment Steps (new GCP project from scratch)

#### Step 1: Create GCP project and enable APIs

```bash
# Create project (or use existing one)
gcloud projects create $PROJECT_ID --name="OAuth2 Passkey Demo"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable artifactregistry.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

#### Step 2: Create Google OAuth2 credentials

1. Open Google Cloud Console > APIs & Services > Credentials
2. Click "Create Credentials" > "OAuth client ID"
3. Application type: "Web application"
4. Name: e.g. "oauth2-passkey-demo"
5. Authorized redirect URIs: `http://localhost:3001/o2p/oauth2/authorized` (placeholder)
6. Save the **Client ID** and **Client Secret**

Note: The Cloud Run redirect URI will be added in Step 6 after deployment.

#### Step 3: Store secrets in Secret Manager

```bash
# Create secrets (first time only)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets create OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets create AUTH_SERVER_SECRET --data-file=-

# Update secrets (add a new version to existing secrets)
echo -n "$OAUTH2_GOOGLE_CLIENT_ID" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_ID --data-file=-
echo -n "$OAUTH2_GOOGLE_CLIENT_SECRET" | gcloud secrets versions add OAUTH2_GOOGLE_CLIENT_SECRET --data-file=-
openssl rand -base64 32 | gcloud secrets versions add AUTH_SERVER_SECRET --data-file=-

# Grant Cloud Run's default service account access to secrets
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format='value(projectNumber)')
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

#### Step 4: Build and push Docker image

```bash
# Create Artifact Registry repository
gcloud artifacts repositories create demo \
  --repository-format=docker \
  --location=asia-northeast1

# Build and push using Cloud Build
gcloud builds submit --config=demo-both/cloudbuild.yaml
```

Note: `demo-both/cloudbuild.yaml` specifies `demo-both/Dockerfile` and the image tag (using `$PROJECT_ID` built-in variable).

Alternatively, build locally and push:
```bash
docker build -f demo-both/Dockerfile \
  -t asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo .
docker push asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo
```

#### Step 5: Deploy to Cloud Run

```bash
# Set env vars from file + secrets (--env-vars-file and --update-env-vars are mutually exclusive)
gcloud run deploy oauth2-passkey-demo \
  --image asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo \
  --region asia-northeast1 \
  --port 8080 \
  --allow-unauthenticated \
  --min-instances 1 \
  --env-vars-file demo-both/env.cloud-run.yaml \
  --set-secrets "OAUTH2_GOOGLE_CLIENT_ID=OAUTH2_GOOGLE_CLIENT_ID:latest,OAUTH2_GOOGLE_CLIENT_SECRET=OAUTH2_GOOGLE_CLIENT_SECRET:latest,AUTH_SERVER_SECRET=AUTH_SERVER_SECRET:latest"

# Set ORIGIN separately (placeholder for first deploy; Step 6 updates to actual URL)
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=https://placeholder.example.com"
```

Note: `--env-vars-file` and `--update-env-vars` cannot be combined in one command.
Environment variables are managed in `demo-both/env.cloud-run.yaml`, and `ORIGIN` is set
separately because it is deployment-specific. Step 6 updates `ORIGIN` to the actual URL.

#### Step 6: Configure ORIGIN and OAuth2 redirect URI

```bash
# Get the Cloud Run service URL
SERVICE_URL=$(gcloud run services describe oauth2-passkey-demo \
  --region asia-northeast1 --format='value(status.url)')
echo "Service URL: $SERVICE_URL"

# Update ORIGIN to the actual Cloud Run URL
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=$SERVICE_URL"
```

Then add the redirect URI in Google Cloud Console:
1. APIs & Services > Credentials > edit the OAuth client
2. Add authorized redirect URI: `$SERVICE_URL/o2p/oauth2/authorized`

#### Step 7: Verify functionality

1. Access `$SERVICE_URL` in browser
2. Test OAuth2 login (Google)
3. Test Passkey registration and authentication
4. Wait 10+ minutes, test OAuth2 login again (JWKS cache refresh)

#### Step 8: Custom domain (optional)

```bash
# Create domain mapping (requires gcloud beta)
gcloud beta run domain-mappings create \
  --service oauth2-passkey-demo \
  --domain passkey-demo.ccmp.jp \
  --region asia-northeast1
```

Add a CNAME record in DNS:
```
passkey-demo.ccmp.jp.  CNAME  ghs.googlehosted.com.
```

Then update ORIGIN and OAuth2 redirect URI:
```bash
gcloud run services update oauth2-passkey-demo \
  --region asia-northeast1 \
  --update-env-vars "ORIGIN=https://passkey-demo.ccmp.jp"
```

Add `https://passkey-demo.ccmp.jp/o2p/oauth2/authorized` as an authorized redirect URI
in Google Cloud Console. SSL certificate is provisioned automatically (10-20 min).

Note: `gcloud run domain-mappings create` (without `beta`) is for Cloud Run for Anthos only.

### Google OAuth2 Notes

- Authentication is free (no charges)
- Test mode: max 100 test users (only added test users can log in)
- Public access requires Google verification review (review is free)
- Redirect URI: `https://<service-name>-<hash>.run.app/o2p/oauth2/authorized`

### Auto-Deploy (GitHub Actions)

```yaml
# .github/workflows/deploy-demo.yml
name: Deploy Demo
on:
  push:
    branches: [dev]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}
      - uses: google-github-actions/deploy-cloudrun@v2
        with:
          service: oauth2-passkey-demo
          source: .
```

Required GitHub repository secrets:
- `GCP_SA_KEY`: Service account JSON key with Cloud Run Admin + Storage Admin roles

### References

- https://cloud.google.com/run/docs
- https://cloud.google.com/run/pricing
- https://cloud.google.com/secret-manager/docs

## Related Files

- `demo-both/DEPLOY.md` - Deployment guide (canonical reference)
- `demo-both/Dockerfile` - Multi-stage build (rust:1.88-alpine -> scratch)
- `demo-both/docker-compose.yml` - Local testing with env_file support
- `demo-both/env.cloud-run.yaml` - Cloud Run environment variables
- `demo-both/cloudbuild.yaml` - Cloud Build config (specifies Dockerfile and image tag)
- `.dockerignore` - Excludes db/, target/, .git/, etc. (stays at root = build context)
- `.gcloudignore` - Excludes files from Cloud Build upload
- `demo-both/src/main.rs` - PORT env var support
- `oauth2_passkey/src/utils.rs` - `get_client()` with optional bundled TLS (`bundled-tls` feature)
- `oauth2_passkey/src/oauth2/discovery.rs` - Uses shared `get_client()`
- `.github/workflows/deploy-demo.yml` (to be created)

## Implementation Tasks

### Docker Image (done)
- [x] Create Dockerfile for demo-both
- [x] Add `.dockerignore`
- [x] Add PORT environment variable support to demo-both
- [x] Remove unnecessary `ring` feature from `rustls`
- [x] Add `webpki-roots` for bundled Mozilla root certificates
- [x] Centralize reqwest Client creation with `use_preconfigured_tls()`
- [x] Migrate Dockerfile to `rust:1.88-alpine` + `scratch` (111MB -> 27.7MB)
- [x] Pass `cargo check`, `cargo clippy`, `cargo test`

### Fixes & Refactoring (done)
- [x] Fix all `reqwest::get()` calls to use shared `get_client()` (aaguid.rs, idtoken.rs x2)
- [x] Create `docker-compose.yml` for local testing (solves `.env` quote handling)
- [x] Verify Docker image runs correctly with `docker compose up`
- [x] Refactor `get_client()` from `oauth2/main/utils.rs` to crate-level `utils.rs`
- [x] Add `bundled-tls` feature flag to make `webpki-roots`/`rustls` optional dependencies

### Deployment
- [x] Step 1: Create GCP project and enable APIs (Run, Artifact Registry, Secret Manager, Cloud Build)
- [x] Step 2: Create Google OAuth2 credentials (Client ID + Secret)
- [x] Step 3: Store secrets in Secret Manager
- [x] Step 4: Build and push Docker image to Artifact Registry
- [x] Step 5: Deploy to Cloud Run
- [x] Step 6: Configure ORIGIN env var and OAuth2 redirect URI
- [x] Step 7: Verify functionality (OAuth2 login, Passkey, JWKS cache refresh)
- [x] Step 8: Custom domain (`passkey-demo.ccmp.jp`)
- Auto-deploy: Moved to separate issue `20260212-1200`

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-01-30: Initial platform selection

- Context: Need public hosting for demo applications
- Decision: Use Fly.io
- Reason: Docker-based (no code changes), Tokyo region available, straightforward
  deployment. Shuttle.rs requires API changes, Cloud Run/Railway are viable
  alternatives but Fly.io is simpler for this use case.

### 2026-02-10: Switch from Fly.io to Cloud Run

- Context: Fly.io no longer offers a free tier (only a 2-hour/7-day trial).
  Investigated 11 platforms: Fly.io, Render, Railway, Shuttle.rs, Koyeb, Zeabur,
  Google Cloud Run, Oracle Cloud, AWS, Azure, Hetzner.
- Decision: Use Google Cloud Run with SQLite + memory cache (no PostgreSQL/Redis)
- Reason: Free tier (180k vCPU-sec, 2M requests/month) is sufficient for a demo.
  No code changes needed. HTTPS and FQDN provided automatically. Data volatility
  is acceptable for a demo site. Oracle Cloud (ARM, $0/month permanent) is a
  viable fallback if persistent storage becomes necessary.

### 2026-02-10: TLS dependency cleanup for scratch Docker image

- Context: Initial Docker image was 111MB (debian:bookworm-slim 75MB + ca-certificates 9MB + binary 27MB).
  Investigated scratch/alpine/distroless alternatives.
- Decision: Bundle Mozilla root certificates via `webpki-roots` + `use_preconfigured_tls()`,
  remove unused `ring` feature from `rustls`, use `rust:1.88-alpine` builder + `scratch` runtime
- Reason: Eliminates runtime `ca-certificates` dependency, enables musl static linking,
  reduces image from 111MB to 27.7MB. reqwest 0.13 removed `rustls-tls-webpki-roots` feature
  flag, so code-level `use_preconfigured_tls()` API is required.

### 2026-02-10: Fix reqwest::get() for scratch container TLS

- Context: Docker image built with webpki-roots but 3 call sites still used `reqwest::get()`
  directly, which creates a default client without bundled certs. In scratch container
  (no OS cert store), all HTTPS requests via these code paths failed with
  `add_parsable_certificates processed 0 valid and 0 invalid certs`.
- Decision: Replace all `reqwest::get()` with `get_client().get().send()`
- Reason: Ensures all HTTP clients use the centralized TLS configuration

### 2026-02-10: Create docker-compose.yml for local testing

- Context: Docker `--env-file` does not strip quotes from `.env` values (unlike `dotenvy`),
  causing `OAUTH2_RESPONSE_MODE='query'` to be parsed as literal `'query'` (with quotes)
- Decision: Use `docker-compose.yml` with `env_file:` directive and `environment:` overrides
- Reason: Docker Compose's `env_file:` handles quotes correctly, and `environment:` overrides
  allow setting container-specific values (PORT, ORIGIN, storage config)

### 2026-02-10: Move get_client() to crate-level utils.rs

- Context: `passkey/main/aaguid.rs` needed `get_client()` but it was in `oauth2/main/utils.rs`,
  creating an architecturally wrong cross-module dependency (`crate::oauth2::get_client()`)
- Decision: Move `get_client()` and `rustls_config_with_webpki_roots()` to `crate::utils`
- Reason: HTTP client is a shared utility, not specific to the OAuth2 module

### 2026-02-10: Add bundled-tls feature flag

- Context: `webpki-roots` and `rustls` are only needed for minimal container images (scratch).
  Normal deployments with OS cert stores don't need them.
- Decision: Make `webpki-roots` and `rustls` optional via `bundled-tls` feature flag,
  propagated through `oauth2-passkey` -> `oauth2-passkey-axum` -> `demo-both`
- Reason: Reduces dependency count for default builds; keeps the library lightweight for
  users who don't need bundled certs. Dockerfile uses `--features bundled-tls`.

### 2026-02-11: Fix in-memory backend stability issues for Docker

- Context: Docker container testing revealed two critical issues with in-memory backends: (1) JWKS cache deadlock after 600s TTL expiry due to tokio::sync::Mutex re-entry in `fetch_jwks_cache()`, and (2) SQLite in-memory tables disappearing after ~30min due to pool idle connection eviction.
- Decision: Three fixes applied: refactor `fetch_jwks_cache()` to use `cache_operations` module (eliminates deadlock), add lazy TTL expiration to `InMemoryCacheStore` (defense in depth), set `min_connections(1)` for in-memory SQLite pools (prevents DB destruction).
- Reason: In-memory SQLite + memory cache is the chosen storage strategy for Docker/Cloud Run deployment. Both issues only manifest with in-memory backends and were not caught during development with Redis/file-based SQLite. See issue `20260211-1742` for detailed analysis.

### 2026-02-12: Strengthen in-memory SQLite pool: disable connection cycling

- Context: `min_connections(1)` alone was insufficient. On Cloud Run, after ~30min the
  `o2p_passkey_credentials` table disappeared again. sqlx's default `max_lifetime` (30min)
  forcibly closes connections; during the close-then-recreate cycle, all connections can
  momentarily reach 0, destroying the in-memory database.
- Decision: Add `idle_timeout(None)` and `max_lifetime(None)` for in-memory SQLite pools
- Reason: In-memory databases have no reason to cycle connections (no leaked resources,
  no stale server-side state). Disabling timeouts eliminates the race condition entirely.

### 2026-02-12: Custom domain for demo site

- Context: Default Cloud Run URL (`*.run.app`) is hard to remember and not suitable for
  public-facing demo links (README, crates.io).
- Decision: Use `passkey-demo.ccmp.jp` via Cloud Run domain mapping (`gcloud beta`)
- Reason: Free (no load balancer needed), auto-managed SSL, memorable URL for
  documentation and sharing. `gcloud run domain-mappings create` (non-beta) is for
  Anthos only; fully managed Cloud Run requires `gcloud beta`.

## Resolution

Demo site successfully deployed to Google Cloud Run at `https://passkey-demo.ccmp.jp`.
All deployment steps (1-8) completed: GCP project setup, OAuth2 credentials, Secret Manager,
Docker image build/push via Cloud Build, Cloud Run deployment, ORIGIN configuration,
functionality verification, and custom domain mapping. Auto-deploy via GitHub Actions
split into separate issue `20260212-1200`.
