# Issue: Optimize Cloud Run Deployment Build Time

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260317-1500

## Created: 2026-03-17-15-00

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Cloud Run deployment for passkey-demo.ccmp.jp takes approximately 25 minutes. The bottleneck
is full Rust compilation from scratch on every build due to zero caching in the current pipeline.

### Current Pipeline Analysis

```
GitHub Actions (push to dev)
  -> gcloud builds submit (uploads source to Cloud Build)
  -> Cloud Build: gcr.io/cloud-builders/docker build
     - Machine: n1-standard-1 (1 vCPU, 3.75 GB RAM) -- DEFAULT
     - Dockerfile: rust:1.88-alpine -> full cargo build -> scratch
     - No layer caching, no cargo cache
     - .gcloudignore excludes target/
  -> Push image to Artifact Registry (asia-northeast1)
  -> gcloud run deploy
```

The 25 minutes is almost entirely Rust compilation of all workspace dependencies (tokio, axum,
sqlx, ring, rustls, etc.) on a single vCPU machine with no caching.

## Related Issues

- `20260212-1200` (completed) - GitHub Actions Auto-Deploy for Cloud Run (original setup)
- `20260315-0348` (completed) - Eliminate aws-lc-sys Dependency (reduced build complexity)

## Approach

### Recommended: Option A - GitHub Actions + BuildKit + cargo-chef

Replace Cloud Build with `docker/build-push-action` on GitHub Actions, using cargo-chef
for dependency layer separation and BuildKit `type=gha` cache.

**Why this is the best fit for the current CI/CD:**

1. **cargo-chef + Kaniko = incompatible** (known issue GoogleContainerTools/kaniko#1520:
   multi-stage `COPY --from=` breaks Kaniko's cache). This rules out the most powerful
   Cloud Build caching option.
2. **Cloud Build Docker `--cache-from`** works but is image-level only (not layer-level),
   and less effective for multi-stage builds with cargo-chef.
3. **GitHub Actions runners** have 4 vCPU / 16 GB RAM vs Cloud Build default 1 vCPU / 3.75 GB.
4. **`type=gha` cache** is layer-level and works seamlessly with BuildKit + cargo-chef.
5. Auth to Artifact Registry works with existing Service Account Key via `docker/login-action`.

**Expected improvement:** 25 min -> ~5 min (first cached build), ~2-3 min (dependency-only cache hit)

#### New Dockerfile (cargo-chef)

```dockerfile
# Stage 1: Install cargo-chef
FROM rust:1.88-alpine AS chef
RUN apk add --no-cache musl-dev cmake make perl
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Analyze dependencies
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Build dependencies (CACHED when only source code changes)
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --manifest-path demo-live/Cargo.toml --features bundled-tls --recipe-path recipe.json
# Build application (only this layer rebuilds on source changes)
COPY . .
RUN cargo build --release --manifest-path demo-live/Cargo.toml --features bundled-tls

# Stage 4: Minimal runtime
FROM scratch
COPY --from=builder /app/target/release/demo-live /demo-live
EXPOSE 8080
ENTRYPOINT ["/demo-live"]
```

#### New Workflow

```yaml
name: Deploy Demo

on:
  push:
    branches: [dev]
    paths:
      - 'oauth2_passkey/**'
      - 'oauth2_passkey_axum/**'
      - 'demo-live/**'
      - '.github/workflows/deploy-demo.yml'

permissions:
  contents: read

env:
  REGION: asia-northeast1
  SERVICE: oauth2-passkey-demo

jobs:
  deploy:
    name: Build and Deploy
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Login to Artifact Registry
        uses: docker/login-action@v3
        with:
          registry: asia-northeast1-docker.pkg.dev
          username: _json_key
          password: ${{ secrets.GCP_SA_KEY }}

      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
          file: demo-live/Dockerfile
          push: true
          tags: asia-northeast1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/demo/${{ env.SERVICE }}:latest
          cache-from: type=gha,scope=demo-live
          cache-to: type=gha,mode=max,scope=demo-live

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Deploy to Cloud Run
        env:
          GCP_PROJECT_ID: ${{ secrets.GCP_PROJECT_ID }}
        run: |
          gcloud run deploy "$SERVICE" \
            --image "${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/demo/${SERVICE}" \
            --region "$REGION" \
            --port 8080 \
            --allow-unauthenticated \
            --min-instances 1 \
            --env-vars-file demo-live/env.cloud-run.yaml \
            --set-secrets "OAUTH2_GOOGLE_CLIENT_ID=OAUTH2_GOOGLE_CLIENT_ID:latest,OAUTH2_GOOGLE_CLIENT_SECRET=OAUTH2_GOOGLE_CLIENT_SECRET:latest,AUTH_SERVER_SECRET=AUTH_SERVER_SECRET:latest"
```

### Alternative: Option B - Cloud Build with `--cache-from` + machine upgrade

If staying with Cloud Build is preferred, two improvements can be combined:

1. **Add `--cache-from`** to cloudbuild.yaml (pull previous image, use as cache)
2. **Upgrade machine** to `N1_HIGHCPU_8` (8 vCPU, 7.2 GB RAM) in cloudbuild.yaml options

```yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['pull', 'asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo:latest']
    id: pull-cache

  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '--cache-from'
      - 'asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo:latest'
      - '-f'
      - 'demo-live/Dockerfile'
      - '-t'
      - 'asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo'
      - '.'
images:
  - 'asia-northeast1-docker.pkg.dev/$PROJECT_ID/demo/oauth2-passkey-demo'
options:
  machineType: 'N1_HIGHCPU_8'
  defaultLogsBucketBehavior: REGIONAL_USER_OWNED_BUCKET
```

**Limitation:** `--cache-from` is image-level caching. With multi-stage builds, only the
final stage benefits. cargo-chef dependency layers won't cache effectively because Cloud Build
Docker doesn't support BuildKit inline cache for intermediate stages without extra configuration.

**Expected improvement:** 25 min -> ~8-12 min (mainly from 8x CPU), limited caching benefit.

### Comparison

| Aspect | Option A (GH Actions + BuildKit) | Option B (Cloud Build + cache) |
|--------|----------------------------------|-------------------------------|
| Expected build time | ~2-5 min (cached) | ~8-12 min |
| Change complexity | Medium (new workflow) | Small (edit cloudbuild.yaml) |
| Caching effectiveness | Excellent (layer-level) | Limited (image-level) |
| cargo-chef compatibility | Full | Partial |
| CPU for compilation | 4 vCPU (free) | 8 vCPU (additional cost) |
| Network to AR | Internet (slower push) | Same-region (fast push) |
| Cost | Free (public repo) | N1_HIGHCPU_8 pricing |

## Related Files

- `.github/workflows/deploy-demo.yml` - Current deployment workflow
- `demo-live/Dockerfile` - Current Dockerfile (no caching)
- `demo-live/cloudbuild.yaml` - Current Cloud Build config
- `.gcloudignore` - Cloud Build upload exclusions

## Implementation Tasks

- [ ] Verify cargo-chef works with current Dockerfile (Alpine musl + workspace)
- [ ] Update `demo-live/Dockerfile` with cargo-chef multi-stage build
- [ ] Update `.github/workflows/deploy-demo.yml` with BuildKit + cache (Option A)
- [ ] Test deployment and measure build time improvement
- [ ] Update `demo-live/DEPLOY.md` if deployment process changes
- [ ] Consider if `demo-live/cloudbuild.yaml` is still needed (manual fallback?)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-03-17: Initial investigation and approach selection

- Context: Cloud Run deployment takes ~25 minutes. Investigated compatibility of
  various caching strategies with current CI/CD (GitHub Actions + Cloud Build).
- Decision: Recommend Option A (GitHub Actions + BuildKit + cargo-chef + type=gha cache)
  over Option B (Cloud Build with --cache-from)
- Reason: cargo-chef is incompatible with Kaniko (the best Cloud Build caching option).
  Cloud Build Docker --cache-from is image-level only, providing limited benefit for
  multi-stage builds. GitHub Actions runners have 4x the CPU of Cloud Build default
  machines, and type=gha cache provides layer-level caching that works well with
  cargo-chef. The project already uses GitHub Actions, so this is a natural fit.

### 2026-03-17: Reference article evaluation

- Context: Evaluated https://zenn.dev/tatsuyasusukida/articles/cloud-run-buildpacks
  (Buildpacks for faster Cloud Run deploys)
- Decision: Not directly applicable
- Reason: Article covers Node.js with Buildpacks (84s -> 50s improvement). This project
  uses Rust where the bottleneck is compilation time (25 min), not the deployment mechanism.
  Buildpacks lack official Rust support. However, the article's core concept of "build
  locally/in CI and push pre-built image" aligns with Option A's approach.

## Resolution
