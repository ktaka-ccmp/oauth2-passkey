# Session Snapshot: GitHub Actions Security Audit

**Date**: 2026-03-04
**Branch**: `fix-exclude-credentials-aaguid-collision` (unrelated — audit was ad-hoc)

## Current Task

Performed a comprehensive security audit of all GitHub Actions workflow files,
prompted by the "hackerbot-claw" AI-powered attack campaign against OSS repositories
(Feb 2026). The audit checked for command injection, `pull_request_target` misuse,
excessive permissions, secrets exposure, self-hosted runner risks, and AI integration safety.

## Files Audited

- `.github/workflows/ci.yml`
- `.github/workflows/coverage.yml`
- `.github/workflows/docs.yml`
- `.github/workflows/deploy-demo.yml`

## Audit Results Summary

| File | Rating | Issues |
|------|--------|--------|
| `ci.yml` | **Warning** | `permissions` not declared |
| `coverage.yml` | **Warning** | `permissions` not declared |
| `docs.yml` | **OK** | Properly configured (permissions set, no risky patterns) |
| `deploy-demo.yml` | **Warning** | `permissions` not declared + `${{ }}` direct expansion in `run:` |

**No Critical issues found.** The repository avoids the most dangerous patterns:
- No `pull_request_target` usage
- No external input (PR title, branch name, etc.) expanded in `run:` steps
- No `self-hosted` runners
- No AI review integrations

## Detailed Findings

### ci.yml — Warning

- **Problem**: No `permissions` declaration at workflow or job level
- **Risk**: Relies on repository default permissions; `pull_request` trigger means external PRs fire this
- **Fix**: Add `permissions: contents: read` after the `on:` block

### coverage.yml — Warning

- **Problem**: No `permissions` declaration
- **Risk**: Same as ci.yml; `codecov/codecov-action@v4` uses `GITHUB_TOKEN` implicitly
- **Fix**: Add `permissions: contents: read` after the `on:` block

### docs.yml — OK

- Permissions properly set: `contents: read`, `pages: write`, `id-token: write`
- Only triggers on `push` to `master` and `workflow_dispatch` (no external PR trigger)
- No `${{ }}` in `run:` steps
- Has `concurrency` to prevent duplicate deploys

### deploy-demo.yml — Warning

- **Problem A**: No `permissions` declaration despite using `secrets.GCP_SA_KEY` and `secrets.GCP_PROJECT_ID`
- **Problem B**: `${{ }}` direct expansion in `run:` step (lines 37-44):
  - `${{ env.REGION }}` — workflow-defined constant (low risk)
  - `${{ env.SERVICE }}` — workflow-defined constant (low risk)
  - `${{ secrets.GCP_PROJECT_ID }}` — secret expanded directly in shell (low practical risk since GCP project IDs are alphanumeric, but bad pattern)
- **Mitigating factor**: Only triggers on `push` to `dev`, not on external PRs
- **Fix**:
  - Add `permissions: contents: read` at job level
  - Move `secrets.GCP_PROJECT_ID` to `env:` block, reference as `$GCP_PROJECT_ID`
  - Reference workflow-level `env` vars as shell vars `$REGION`, `$SERVICE` instead of `${{ env.REGION }}`

#### Proposed deploy-demo.yml fix (Deploy to Cloud Run step):

```yaml
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

## Pending Actions (Not Yet Implemented)

### 1. Fix workflow files
Apply `permissions` declarations to `ci.yml`, `coverage.yml`, `deploy-demo.yml` and
refactor `deploy-demo.yml` to use `env:` instead of direct `${{ }}` expansion in `run:`.

### 2. Add GitHub Actions security policy to global CLAUDE.md

**Location**: `~/.claude/CLAUDE.md` (global, applies to all projects on all machines)

The policy is repository-agnostic, so it belongs in the global config rather than
project-level CLAUDE.md. Append the following to `~/.claude/CLAUDE.md`:

```markdown
## GitHub Actions Security Policy

When creating or modifying GitHub Actions workflows (`.github/workflows/*.yml`):

- **Never expand `${{ }}` directly in `run:` steps.** Pass values through `env:` and reference as shell variables (`$VAR_NAME`). Prevents command injection via externally-controllable inputs
- **Never use `pull_request_target` to checkout and execute PR branch code.** This event runs with base repository secrets and write access
- **Always declare `permissions` explicitly.** Set `contents: read` as baseline, add only what's needed
- **Never expose `secrets.*` in `run:` steps via `${{ }}`.** Use `env:` or action `with:` parameters
- **Audit workflows with `/audit-workflows`** after any workflow changes
```

### 3. Create audit-workflows custom command (global)

**Location**: `~/.claude/commands/audit-workflows.md` (global, available in all projects)

The audit command is not project-specific, so it belongs in the global commands directory.
Content includes all 6 check categories and output format (see session conversation for full draft).

### Note on multi-machine deployment

Both items (2 and 3) should be applied to `~/.claude/` on **all development machines**.
The snapshot contains the full content for both files so they can be reproduced on other machines.

## Reference Links

- https://www.stepsecurity.io/blog/hackerbot-claw-github-actions-exploitation
- https://zenn.dev/aeyesec/articles/417578718dcced

## Context

- The audit was triggered by reading about the hackerbot-claw campaign
- The user's open issue file (`20260226-2030-aaguid-credential-deletion-collision.md`) was open in IDE but unrelated
- Current branch work (`fix-exclude-credentials-aaguid-collision`) should be completed first before creating a separate branch for the workflow fixes
