# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

## Development Tips

1. When modifying authentication flows, changes typically need to be made in:
   - `oauth2_passkey/src/coordination/` for core logic
   - `oauth2_passkey_axum/src/` for HTTP handlers

2. Static assets (JS/CSS) are in `oauth2_passkey_axum/src/assets/`

3. Database migrations are handled automatically by the storage layer

4. For debugging authentication issues, check the coordination layer logs first