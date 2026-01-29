# CI/CD

This chapter covers the CI/CD pipelines configured for the OAuth2-Passkey project using GitHub Actions.

## Overview

The project has three GitHub Actions workflows:

| Workflow | File | Purpose |
|----------|------|---------|
| CI | `ci.yml` | Testing, linting, security audit |
| Coverage | `coverage.yml` | Code coverage reporting |
| Documentation | `docs.yml` | GitHub Pages deployment |

## CI Workflow

The main CI workflow (`.github/workflows/ci.yml`) runs on every push and pull request to `master` and `develop` branches.

### Jobs

#### Test Suite

Runs tests across multiple Rust versions:

| Version | Required | Purpose |
|---------|----------|---------|
| stable | Yes | Primary testing target |
| beta | No (can fail) | Early warning for upcoming changes |
| nightly | No (can fail) | Bleeding edge compatibility |

**Steps performed (stable only):**
1. Check formatting (`cargo fmt --all -- --check`)
2. Run clippy (`cargo clippy --all-targets --all-features`)

**Steps performed (all versions):**
1. Build core library (`oauth2_passkey`)
2. Build Axum integration (`oauth2_passkey_axum`)
3. Test core library
4. Test Axum integration (with all features)
5. Test Axum integration (with no default features)

#### Security Audit

Runs `cargo audit` to check for known vulnerabilities in dependencies.

```yaml
- name: Run security audit
  run: cargo audit --ignore RUSTSEC-2023-0071
```

The `--ignore` flag excludes known advisories that have been reviewed and accepted.

#### Documentation Build

Verifies that rustdoc builds without warnings:

```yaml
- name: Build documentation
  run: |
    cargo doc --no-deps --manifest-path oauth2_passkey/Cargo.toml
    cargo doc --no-deps --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
  env:
    RUSTDOCFLAGS: "-D warnings"
```

#### MSRV Check

Verifies compatibility with the Minimum Supported Rust Version (currently 1.88):

```yaml
- name: Install Rust 1.88
  uses: dtolnay/rust-toolchain@stable
  with:
    toolchain: "1.88"

- name: Check MSRV compatibility
  run: |
    cargo check --manifest-path oauth2_passkey/Cargo.toml
    cargo check --manifest-path oauth2_passkey_axum/Cargo.toml --all-features
```

## Coverage Workflow

The coverage workflow (`.github/workflows/coverage.yml`) generates code coverage reports on pushes and pull requests to `master`.

### How It Works

1. **Generate Coverage**: Uses `cargo-llvm-cov` to run tests with coverage instrumentation

   ```yaml
   - name: Generate coverage report
     run: cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
   ```

2. **Upload to Codecov**: Sends coverage data to Codecov for tracking and visualization

   ```yaml
   - name: Upload coverage to Codecov
     uses: codecov/codecov-action@v4
   ```

3. **Archive Report**: Saves the coverage report as a GitHub artifact (retained for 30 days)

### Viewing Coverage

- **Codecov Dashboard**: View coverage trends and file-level details at codecov.io
- **GitHub Artifacts**: Download `lcov.info` from the workflow run's artifact section

## Documentation Workflow

The documentation workflow (`.github/workflows/docs.yml`) deploys the mdBook documentation to GitHub Pages.

### Deployment URL

The documentation is published at:

```
https://ktaka-ccmp.github.io/oauth2-passkey/
```

This URL follows GitHub's standard naming convention:

```
https://{username}.github.io/{repository-name}/
```

This is a fixed GitHub Pages specification and cannot be changed (unless you configure a custom domain).

### Triggers

```yaml
on:
  push:
    branches:
      - master
    paths:
      - 'docs/**'
      - '.github/workflows/docs.yml'
  workflow_dispatch:
```

- **Automatic**: Push to `master` branch with changes in `docs/` directory
- **Manual**: Trigger via `workflow_dispatch` from GitHub Actions UI

### How It Works

1. **Build Step**: mdBook compiles the documentation from `docs/src/` into static HTML in `docs/book/`

   ```yaml
   - name: Build documentation
     run: mdbook build docs
   ```

2. **Upload Step**: The generated `docs/book/` directory is uploaded as a GitHub Pages artifact

   ```yaml
   - name: Upload artifact
     uses: actions/upload-pages-artifact@v3
     with:
       path: 'docs/book'
   ```

3. **Deploy Step**: The artifact is deployed to GitHub Pages

   ```yaml
   - name: Deploy to GitHub Pages
     uses: actions/deploy-pages@v4
   ```

### Required GitHub Settings

For this workflow to function, the repository must have GitHub Pages configured:

1. Go to **Settings** → **Pages**
2. Under **Source**, select **GitHub Actions**

This enables the `actions/deploy-pages` action to publish content to GitHub Pages.

## Summary

| Workflow | Trigger | Key Outputs |
|----------|---------|-------------|
| CI | Push/PR to master, develop | Test results, lint status |
| Coverage | Push/PR to master | Coverage report on Codecov |
| Documentation | Push to master (docs/) | Live site at GitHub Pages |
