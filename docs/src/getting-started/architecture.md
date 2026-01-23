# Chapter 3: Architecture

## Overview

This chapter describes the architecture of the oauth2-passkey library.

## Current Components

- **demo-both**: Example Axum application that uses both OAuth2 and passkey authentication
- **demo-oauth2**: Example Axum application using OAuth2-only authentication
- **demo-passkey**: Example Axum application using passkey-only authentication
- **oauth2_passkey_axum**: Provides OAuth2 and passkey authentication handlers for Axum applications
  - Includes routers for OAuth2, passkey, and user summary endpoints
  - Handles HTTP-specific concerns like request/response handling
- **oauth2_passkey**: Core authentication coordination library
  - **config**: Environment variable configuration management
  - **coordination**: Central coordination layer that orchestrates authentication flows
  - **oauth2**: OAuth2 authentication operations, stores OAuth2 accounts
  - **passkey**: Passkey/WebAuthn operations, stores passkey credentials
  - **session**: Session management using cache store, provides session cookies
  - **storage**: Cache and SQL store providers (PostgreSQL and SQLite support)
  - **userdb**: User database operations, provides user_id management
  - **utils**: Common utility functions

## Component Responsibilities

### oauth2_passkey (Core Library)

- **coordination**: Provides a unified API for authentication operations
  - Orchestrates the authentication flows between different modules
  - Handles error mapping and coordination between components
  - Exposes high-level functions for authentication operations

- **oauth2**: Handles OAuth2 authentication
  - Manages OAuth2 provider integration
  - Stores and retrieves OAuth2 accounts
  - Handles OAuth2 authentication flow (authorization, token exchange)

- **passkey**: Handles WebAuthn/Passkey authentication
  - Manages passkey registration and authentication
  - Stores and retrieves passkey credentials
  - Implements WebAuthn protocol for credential verification

- **session**: Manages user sessions
  - Creates and validates session tokens
  - Handles session cookies and page session tokens
  - Provides user information from sessions

- **storage**: Provides data persistence
  - Implements cache storage for temporary data
  - Provides SQL database access for persistent data
  - Supports both PostgreSQL and SQLite

- **userdb**: Manages user accounts
  - Creates and updates user records
  - Provides user lookup functionality
  - Links authentication methods to user accounts

### oauth2_passkey_axum (Axum Integration)

- Provides Axum-specific HTTP handlers and routers
- Translates between HTTP requests/responses and core library functions
- Manages authentication middleware for Axum applications

## Security Considerations

- Session tokens are securely managed with proper expiration
- Page session tokens provide protection against session desynchronization
- Passkey credentials follow WebAuthn security standards
- OAuth2 implementation follows best practices for authorization flow

## Data Flow

```
                         ┌─────────────────┐
                         │     Browser     │
                         └────────┬────────┘
                                  │ HTTP Request
                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        oauth2_passkey_axum                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐  │
│  │   Router    │───▶│  Handlers   │───▶│   Static Assets (UI)    │  │
│  └─────────────┘    └──────┬──────┘    └─────────────────────────┘  │
└────────────────────────────┼────────────────────────────────────────┘
                             │ calls
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          oauth2_passkey                             │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                       coordination                            │  │
│  │              (orchestrates authentication flows)              │  │
│  └───────┬─────────────┬─────────────┬─────────────┬─────────────┘  │
│          │             │             │             │                │
│          ▼             ▼             ▼             ▼                │
│    ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│    │  oauth2  │  │ passkey  │  │ session  │  │  userdb  │          │
│    │          │  │          │  │          │  │          │          │
│    │  Google  │  │ WebAuthn │  │ cookies  │  │ accounts │          │
│    │  OIDC    │  │ FIDO2    │  │ tokens   │  │ linking  │          │
│    └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│         │             │             │             │                 │
│         └─────────────┴──────┬──────┴─────────────┘                 │
│                              ▼                                      │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                         storage                               │  │
│  │  ┌─────────────────────┐    ┌──────────────────────────────┐  │  │
│  │  │     cache_store     │    │         data_store           │  │  │
│  │  │  (session, CSRF,    │    │  (users, credentials,        │  │  │
│  │  │   WebAuthn state)   │    │   OAuth2 accounts)           │  │  │
│  │  └──────────┬──────────┘    └───────────────┬──────────────┘  │  │
│  └─────────────┼───────────────────────────────┼─────────────────┘  │
└────────────────┼───────────────────────────────┼────────────────────┘
                 │                               │
                 ▼                               ▼
        ┌────────────────┐              ┌────────────────┐
        │ Memory / Redis │              │ SQLite / PgSQL │
        └────────────────┘              └────────────────┘
```

### Request Flow Example (Passkey Authentication)

1. Browser sends authentication request to `/o2p/passkey/auth/start`
2. Router dispatches to passkey handler in `oauth2_passkey_axum`
3. Handler calls `coordination` layer in `oauth2_passkey`
4. Coordination orchestrates:
   - `session` validates existing session state
   - `passkey` generates WebAuthn challenge (stored in `cache_store`)
5. Response returns to browser with challenge
6. Browser completes WebAuthn ceremony, sends assertion
7. `passkey` verifies assertion against stored credential (`data_store`)
8. `session` creates authenticated session (stored in `cache_store`)
9. `userdb` retrieves user information
10. Response returns with session cookie

### Key Design Points

- **coordination** is the central orchestration layer - all auth flows go through it
- **oauth2** and **passkey** modules are independent (no cross-dependencies)
- **cache_store** handles temporary data (sessions, CSRF tokens, WebAuthn challenges)
- **data_store** handles persistent data (users, credentials, OAuth2 accounts)

## Future Directions

- Further consolidation of related functionality
- Enhanced error handling and logging with standardization on thiserror
- Additional authentication methods
- Improved documentation and examples
