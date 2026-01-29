# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Guidelines

**CRITICAL**: Always observe these fundamental principles:
- **Never go beyond the scope of the request**
- **Never shortcut what was requested**
- Must read ~/.claude/CLAUDE.md

These guidelines ensure focused, complete work that addresses exactly what the user needs without unnecessary additions or omissions.

## Project Overview

This is a Rust authentication library providing OAuth2 (Google) and WebAuthn/Passkey authentication for web applications, with Axum framework integration.

## Key Commands

### Build & Test
```bash
# Build entire workspace
cargo build

# Build with all features (required for Axum integration)
cargo build --manifest-path oauth2_passkey_axum/Cargo.toml --all-features

# Run all tests
cargo test

# Run tests for specific crate
cargo test --manifest-path oauth2_passkey/Cargo.toml
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features

# Check code quality
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
```

## Code Quality Standards

**CRITICAL**: Always run these commands after making code changes (in this order):

1. **Format code**: `cargo fmt --all` (handles all Rust file formatting including whitespace)
2. **Check quality**: `cargo clippy --all-targets --all-features` (finds potential issues)
3. **Run tests**: `cargo test` (verifies functionality)

**Clippy Standards**: Fix ALL warnings before committing code. Clippy warnings indicate potential issues that should be addressed:

- Use `#[allow(clippy::lint_name)]` only when absolutely necessary with clear justification
- Prefer fixing the underlying issue rather than suppressing warnings
- Run clippy after any significant code changes
- Address dead code, unused imports, and style issues promptly

**Claude Code Workflow**: After completing any task involving code changes, always run `cargo fmt --all` to ensure consistent formatting before finishing.

**File-Type Specific Formatting**:
- **Rust files** (`.rs`): `cargo fmt --all` handles all formatting including whitespace
- **Non-Rust files** (`.md`, `.toml`, `.sh`, etc.): Manual whitespace cleanup may be needed
  - Remove trailing spaces: `sed -i -e 's/^[[:space:]]*$//g' -e 's/[[:space:]]*$//' filename`
  - Utility script: `./utils/cleanup_whitespace.sh` (for non-Rust files only)

### Run Demo Applications
```bash
# Combined OAuth2 + Passkey demo
cd demo-both && cargo run

# OAuth2-only demo
cd demo-oauth2 && cargo run

# Passkey-only demo
cd demo-passkey && cargo run
```

### Database Setup
```bash
# Start PostgreSQL and Redis
cd db && docker compose up -d

# Clear database and cache
./utils/clear_db_cache.sh
```

## Architecture

### Core Structure
- **oauth2_passkey/** - Core authentication library
  - `coordination/` - Central orchestration of auth flows
  - `oauth2/` - OAuth2 implementation
  - `passkey/` - WebAuthn/Passkey implementation
  - `session/` - Session management
  - `storage/` - Database (SQLite/PostgreSQL) and cache (Memory/Redis) abstraction
  - `userdb/` - User account management

- **oauth2_passkey_axum/** - Axum web framework integration
  - HTTP handlers and routers
  - Static assets (JS/CSS) in `src/assets/`
  - HTML templates in `src/templates/`

### Key Design Principles
1. **Layered Architecture**: Clear separation between core logic and web framework
2. **Coordination Layer**: All authentication flows go through the coordination module
3. **Flexible Storage**: Supports both development (SQLite, in-memory) and production (PostgreSQL, Redis) setups
4. **Security First**: Built-in CSRF protection, secure sessions, page session tokens

### Configuration
Environment variables (see `dot.env.example`):
- **Required**: `ORIGIN`, `OAUTH2_GOOGLE_CLIENT_ID`, `OAUTH2_GOOGLE_CLIENT_SECRET`
- **Storage**: `CACHE_TYPE` (memory/redis), `DB_TYPE` (sqlite/postgresql)
- **Optional**: WebAuthn settings, cookie configuration, route prefixes

### Testing Strategy
- Unit tests colocated with modules
- Integration tests in `/tests/` directories
- Use in-memory databases for fast testing
- See `docs/TestStrategy.md` for testing best practices

## Development Guidelines

### Library Design Principles
1. **Publication Ready**: Code should be suitable for publishing on crates.io
2. **Simplicity First**: Make code as simple as possible while remaining feasible
3. **Minimal Dependencies**: Reduce dependencies on external crates where possible
4. **Error Handling**: Use `thiserror` crate instead of `anyhow` (better for library crates)
5. **Documentation**: Include comprehensive tutorials and examples
6. **Minimal Visibility**: Keep module internals private, re-export only necessary items

### Development Workflow
7. **Minimal Changes**: Code modifications should be minimal and targeted to fulfill specific needs
8. **Change Approval**: Discuss and get explicit approval before making changes beyond the immediate request
9. **Meaningful Commits**: Commit messages should reflect actual changes made and their intentions
10. **Error Safety**: Avoid `unwrap()` or `expect()` unless absolutely reasonable (except in unit tests)

### Testing Standards
11. **Incremental Testing**: Write unit tests one by one, ensuring each passes before writing the next
12. **Approval Required**: Ask for approval before proceeding to next file or writing multiple tests
13. **Non-Invasive**: Never modify original functions when writing tests without explanation and permission
14. **Test Placement**: Place inline unit tests at the bottom of files
15. **Use Test Utils**: Utilize the `test_utils` module for data store and cache initialization
16. **Functional Testing**: Test actual functionality by calling functions, not mimicking behavior

### Documentation Standards
17. **Fact-Based Only**: Never make assumptions about codebase structure or implementation
18. **Verify First**: Always examine actual code using tools before making statements
19. **Explicit Uncertainty**: Use phrases like "Based on examination of..." when documenting
20. **Error Prevention**: STOP → Verify → Use Tools → Examine Code → Document Facts

## Development Tips

1. When modifying authentication flows, changes typically need to be made in:
   - `oauth2_passkey/src/coordination/` for core logic
   - `oauth2_passkey_axum/src/` for HTTP handlers

2. Static assets (JS/CSS) are in `oauth2_passkey_axum/src/assets/`

3. Database migrations are handled automatically by the storage layer

4. For debugging authentication issues, check the coordination layer logs first

## Release Process

### Quick Reference
```bash
# 1. Merge dev -> master via PR first, then:
git checkout master
git pull origin master

# 2. Dry-run to verify
./utils/release.sh -d -v 0.2.0

# 3. Execute release
./utils/release.sh -e -v 0.2.0
```

### What the Script Does
- Creates `release-X.Y.Z` branch from master
- Sets version in `Cargo.toml`
- Publishes `oauth2-passkey` to crates.io
- Waits for crates.io availability
- Updates dependency, publishes `oauth2-passkey-axum`
- Creates git tag `vX.Y.Z`
- Sets next dev version (`X.Y.(Z+1)-dev`)
- Creates PR back to master

### Version Guidelines
- **Patch** (0.1.3 -> 0.1.4): Bug fixes only
- **Minor** (0.1.x -> 0.2.0): New features or breaking changes
- **Major** (0.x -> 1.0): Stable API release

### Post-Release Steps

After the release script completes:

```bash
# 1. Verify on crates.io
#    - https://crates.io/crates/oauth2-passkey
#    - https://crates.io/crates/oauth2-passkey-axum

# 2. Merge release branch to master via GitHub PR
#    - The script creates a PR automatically (requires gh CLI)
#    - Or create manually: release-X.Y.Z -> master

# 3. Update local master
git checkout master
git pull origin master

# 4. Sync dev branch with master
git checkout dev
git rebase master

# 5. Push dev branch (force required after rebase)
git push origin dev --force-with-lease

# 6. Clean up release branch (optional, if not auto-deleted)
git branch -d release-X.Y.Z
git push origin --delete release-X.Y.Z
```

**Note on `--force-with-lease`**:
- Safer than `--force`: fails if remote has commits you haven't fetched
- Required after rebase because commit history is rewritten
- Prevents accidentally overwriting others' work on the branch

## Workflow Tools

This project uses Claude Code commands for workflow management.

### Available Commands

| Command | Description |
|---------|-------------|
| `/snapshot` | Create a session snapshot for context transfer between machines |
| `/issue` | Create or update an issue for task/bug tracking |
| `/backlog` | View all open issues |

### Session Snapshots (`.claude/sessions/`)

For transferring work context between machines or sessions:
- **Purpose**: Capture current work state for resumption
- **Filename**: `YYYY-MM-DD-<topic>.md`
- **Content**: Current task, files modified, key decisions, next steps, context

### Issue Tracking (`.claude/issues/`)

For persistent task and bug tracking across sessions:
- **Purpose**: Track tasks that span multiple sessions
- **Filename**: `YYYY-MM-DD-<short-slug>.md`
- **Status**: `open`, `completed`, `wontfix`, `deferred`
- **Priority**: `high`, `medium`, `low`
- **Structure**: `open/`, `completed/`, `deferred/` subdirectories

### When to Use Each

| Scenario | Use |
|----------|-----|
| Switching machines mid-task | `/snapshot` |
| End of day work capture | `/snapshot` |
| Feature request to implement later | `/issue` |
| Bug found but not fixing now | `/issue` |
| Check pending work | `/backlog` |
| Planning next session | `/backlog` then read relevant snapshots |

## Commit Message Guidelines

1. **Use ASCII characters only** for better copy-paste compatibility:
   - Use "->" instead of "→" in commit messages
   - Avoid Unicode symbols that may cause issues in different terminals/systems
   - This ensures commit messages can be easily copied and pasted across all environments

- Investigation should never be superficial, should always be deep and thorough.

- Be critical about declaring tasks complete. I’ve seen you claim completion and highlight progress while substantial work was still pending.
