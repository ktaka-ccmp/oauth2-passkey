# Issue: GitHub Actions Auto-Deploy for Cloud Run

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260212-1200

## Created: 2026-02-12-12-00

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

Set up GitHub Actions workflow to automatically build and deploy the demo site
to Google Cloud Run when changes are pushed to master. Currently deployment
requires manual `gcloud builds submit` and `gcloud run deploy` commands.

Split from issue `2026-01-30-08` (Demo Site Deployment).

## Related Issues

- `2026-01-30-08` (completed) - Demo Site Deployment (Cloud Run)
- `20260212-0235` - Standalone Demo Repository

## Approach

### Authentication: Service Account Key (simple)

For a demo site, Service Account Key is sufficient. Workload Identity Federation
(OIDC, keyless) is more secure but adds setup complexity.

### GCP Setup

```bash
# 1. Create service account
gcloud iam service-accounts create github-actions-deploy \
  --display-name="GitHub Actions Deploy"

# 2. Grant roles
PROJECT_ID=$(gcloud config get-value project)
SA_EMAIL="github-actions-deploy@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/run.admin"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/iam.serviceAccountUser"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/cloudbuild.builds.editor"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/artifactregistry.writer"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" --role="roles/storage.admin"

# 3. Generate JSON key
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=$SA_EMAIL

# 4. Add repository secrets in GitHub:
#    Repository page > Settings > Secrets and variables > Actions > "New repository secret"
#    - GCP_SA_KEY: paste sa-key.json contents
#    - GCP_PROJECT_ID: your GCP project ID
# 5. Delete local key: rm sa-key.json
```

### Workflow File

```yaml
# .github/workflows/deploy-demo.yml
name: Deploy Demo

on:
  push:
    branches: [master]
    paths:
      - 'oauth2_passkey/**'
      - 'oauth2_passkey_axum/**'
      - 'demo-live/**'
      - '.github/workflows/deploy-demo.yml'

env:
  PROJECT_ID: <PROJECT_ID>
  REGION: asia-northeast1
  SERVICE: oauth2-passkey-demo
  IMAGE: asia-northeast1-docker.pkg.dev/<PROJECT_ID>/demo/oauth2-passkey-demo

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to Google Cloud
        uses: google-github-actions/auth@v2
        with:
          credentials_json: ${{ secrets.GCP_SA_KEY }}

      - name: Set up Cloud SDK
        uses: google-github-actions/setup-gcloud@v2

      - name: Build with Cloud Build
        run: gcloud builds submit --config=demo-live/cloudbuild.yaml

      - name: Deploy to Cloud Run
        run: |
          gcloud run deploy $SERVICE \
            --image $IMAGE \
            --region $REGION
```

### Key Design Decisions

- **Trigger branch**: `master` (not `dev`) - only deploy stable code
- **`paths` filter**: Only trigger when relevant code changes (not README edits)
- **Cloud Build**: Reuse existing `demo-live/cloudbuild.yaml` for image build
- **Deploy only updates image**: Env vars and secrets are already configured on Cloud Run

### Optional: Workload Identity Federation (more secure)

If upgrading to keyless auth later:

```bash
# Create Workload Identity Pool + OIDC Provider
gcloud iam workload-identity-pools create "github-pool" \
  --location="global" --display-name="GitHub Actions Pool"

gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --location="global" --workload-identity-pool="github-pool" \
  --display-name="GitHub Provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# Bind service account
gcloud iam service-accounts add-iam-policy-binding $SA_EMAIL \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-pool/attribute.repository/OWNER/REPO"
```

Workflow auth changes to:
```yaml
      - uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider'
          service_account: 'github-actions-deploy@PROJECT_ID.iam.gserviceaccount.com'
```

## Related Files

- `.github/workflows/deploy-demo.yml` (to be created)
- `demo-live/cloudbuild.yaml` - Cloud Build config (reused by workflow)
- `demo-live/DEPLOY.md` - Deployment guide

## Implementation Tasks

- [ ] Create GCP service account with required IAM roles
- [ ] Generate JSON key and add to GitHub repository secrets (`GCP_SA_KEY`, `GCP_PROJECT_ID`)
- [x] Create `.github/workflows/deploy-demo.yml`
- [ ] Test workflow by pushing to master
- [x] Update `demo-live/DEPLOY.md` with auto-deploy section

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-12: Split from deployment issue

- Context: Demo site deployment (issue `2026-01-30-08`) steps 1-8 completed.
  Auto-deploy is a distinct task requiring GCP service account, GitHub secrets, and workflow file.
- Decision: Create separate issue for auto-deploy
- Reason: Clean separation of concerns; deployment issue can be closed as completed

## Resolution
