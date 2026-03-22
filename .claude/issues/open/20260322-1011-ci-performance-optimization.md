# Issue: CI Performance Optimization

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260322-1011

## Created: 2026-03-22

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

CI runs take 6-12 minutes wall-clock and 24-43 minutes billable time. The primary bottleneck is `actions/cache` handling ~10 GiB caches (entire `target/` directory), which takes 3-4 minutes to restore per job.

### Current timing breakdown (cache-hit run)

| Job | Total | Cache Restore | Actual Work | Cache Save |
|-----|-------|---------------|-------------|------------|
| Test Suite (stable) | 6m | 3.4m | 2.5m | 0s |
| Test Suite (beta) | 5.2m | 3.1m | 2m | 0s |
| Test Suite (nightly) | 5.4m | 3.4m | 1.9m | 0s |
| Documentation | 3.3m | 2.9m | 0.3m | 0s |
| Security Audit | 3m | 0 | 2.9m (compile cargo-audit) | 0 |
| MSRV | 1.7m | 0 | 1.6m | 0 |

Coverage workflow (separate): 4-7 minutes, same cache bottleneck.

### Root causes

1. **`actions/cache` with full `target/` = ~10 GiB per cache entry**: Download + extraction dominates every job (170-221s)
2. **`cargo install cargo-audit` compiles from source**: 172s every run, when pre-built binary takes ~2s
3. **Beta + nightly run on every PR**: `continue-on-error: true`, purely informational, but cost 10-24 min billable
4. **Same dependency tree compiled 5-6 times**: Each job independently restores/compiles

## Related Issues

None

## Approach

### Phase 1: Quick wins (small effort, large impact)

#### 1a. Switch `actions/cache` to `Swatinem/rust-cache@v2` in ci.yml and coverage.yml

Swatinem/rust-cache v2.9.1 is Rust-specific and:
- Caches only dependency artifacts (not workspace crates or incremental data)
- Auto-generates cache keys from rustc version + Cargo.lock + Cargo.toml
- Cleans `target/` before saving (removes stale files, workspace artifacts)
- Sets `CARGO_INCREMENTAL=0` automatically
- Typically reduces cache size from ~10 GiB to 1-2 GiB

Replace the 8-line `actions/cache` blocks with:

```yaml
- uses: Swatinem/rust-cache@v2
  with:
    save-if: ${{ github.ref == 'refs/heads/master' || github.ref == 'refs/heads/dev' }}
    cache-on-failure: true
```

- `save-if`: PRs restore base branch cache but don't save (avoids 10 GiB limit pollution)
- `cache-on-failure: true`: Save compiled deps even if tests fail
- Matrix builds get separate caches automatically via rustc version hash

**Expected impact**: Cache restore 3-4min -> 10-30s per job. Largest single improvement.

#### 1b. Use `taiki-e/install-action@cargo-audit` instead of `cargo install cargo-audit`

Replace:
```yaml
- name: Install cargo-audit
  run: cargo install cargo-audit
```

With:
```yaml
- name: Install cargo-audit
  uses: taiki-e/install-action@cargo-audit
```

Downloads pre-built binary (~2s) instead of compiling from source (~172s).

#### 1c. Remove redundant `cargo build` steps in ci.yml

`cargo test` implicitly builds. The separate `cargo build` steps add ~19s and provide no additional signal.

### Phase 2: Structural improvements (medium effort)

#### 2a. Move beta/nightly to weekly schedule

Create a separate `ci-nightly.yml` with `schedule: cron` (e.g., weekly on Monday). Keep only stable in the main CI workflow. This removes 2 of 3 matrix entries.

#### 2b. Split fmt/clippy into a fast lint job

Create a lightweight `lint` job (fmt + clippy) that other jobs depend on via `needs: lint`. If linting fails, test jobs are skipped entirely.

#### 2c. Add cache to MSRV and Security Audit jobs

Both currently run without caching. Adding `Swatinem/rust-cache@v2` to MSRV would save ~30-60s. Security audit with the pre-built binary fix (1b) makes caching unnecessary.

### Phase 3: Advanced (larger effort, diminishing returns)

#### 3a. Use `sccache` for shared compilation cache

Share compiled artifacts across jobs via `sccache` + GitHub Actions cache backend. Would eliminate redundant compilation of the same dependency tree across stable/docs/coverage.

### Expected results

| Optimization | Wall-clock savings | Billable savings |
|---|---|---|
| Swatinem/rust-cache (1a) | 3-4 min/job | 15-20 min total |
| Pre-built cargo-audit (1b) | 2.8 min | 2.8 min |
| Remove cargo build (1c) | 0.3 min | 1 min |
| Beta/nightly weekly (2a) | 0 (parallel) | 10-20 min |
| **Phase 1 total** | **~3-4 min** | **~19-24 min** |
| **Phase 1+2 total** | **~3-4 min** | **~29-44 min** |

### Caveats for Swatinem/rust-cache

- Nightly cache invalidates daily (nightly toolchain changes) -- another reason to make it weekly
- Coverage job will get a separate cache automatically (different job ID)
- 10 GiB total cache limit shared across all branches -- `save-if` on PRs is important
- Known issue: workspace root `Cargo.toml` changes may not invalidate cache (#268 in rust-cache repo)

## Related Files

- `.github/workflows/ci.yml`
- `.github/workflows/ci-nightly.yml` (new, weekly beta/nightly)
- `.github/workflows/coverage.yml`
- `.github/workflows/docs.yml` (no changes needed, already fast at 22-27s)
- `.github/workflows/deploy-demo.yml` (no changes needed, Docker-based)

## Implementation Tasks

### Phase 1
- [x] Switch ci.yml from `actions/cache` to `Swatinem/rust-cache@v2`
- [x] Switch coverage.yml from `actions/cache` to `Swatinem/rust-cache@v2`
- [x] Replace `cargo install cargo-audit` with `taiki-e/install-action@cargo-audit`
- [x] Remove redundant `cargo build` steps in ci.yml
- [x] Add `Swatinem/rust-cache@v2` to docs job in ci.yml
- [x] Add `Swatinem/rust-cache@v2` to MSRV job in ci.yml
- [ ] Verify all CI jobs pass after changes
- [ ] Compare timing before/after

### Phase 2
- [x] Move beta/nightly to weekly scheduled workflow (ci-nightly.yml)
- [x] Split fmt/clippy into fast lint job with `needs: lint` dependency

## Decision Log

### 2026-03-22: Issue created from CI performance investigation

- Context: CI runs taking 6-12 minutes wall-clock, with cache restore/save consuming more time than actual builds and tests. `actions/cache` caching entire `target/` (~10 GiB) is the root cause.
- Decision: Phased approach -- Phase 1 (quick wins with Swatinem/rust-cache, pre-built cargo-audit, remove redundant builds) should cut billable time by ~50%. Phase 2 (weekly nightly, lint job) for further optimization.
- Reason: Phase 1 changes are low-risk and high-impact. Phase 2 requires workflow restructuring. Phase 3 (sccache) has diminishing returns and complexity.

### 2026-03-22: Implemented Phase 1 + Phase 2

- Context: Implementing CI performance optimizations.
- Decision: Implemented Phase 1 (Swatinem/rust-cache, pre-built cargo-audit, remove redundant builds, add cache to msrv) and Phase 2 (lint job split, beta/nightly to weekly ci-nightly.yml) together. Skipped Phase 3 (sccache) due to diminishing returns.
- Reason: Phase 1+2 combined address all high-impact optimizations. Phase 3 adds complexity with minimal additional benefit after rust-cache already handles dependency caching.

## Resolution