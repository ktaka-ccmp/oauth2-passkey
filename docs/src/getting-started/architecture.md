# Chapter 3: Architecture

## Overview

This chapter describes the architecture of the oauth2-passkey library.

## Current Components

- **demo-both**: Example Axum application that uses both OAuth2 and passkey authentication
- **demo-oauth2**: Example Axum application using OAuth2-only authentication
- **demo-passkey**: Example Axum application using passkey-only authentication
- **demo-custom-login**: Example Axum application with custom login and account pages
- **demo-profile**: Example Axum application demonstrating user profile management
- **demo-todo**: Example Axum application demonstrating a todo list with authentication
- **oauth2_passkey_axum**: Provides OAuth2 and passkey authentication handlers for Axum applications
  - Includes routers for OAuth2, passkey, and user account endpoints
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
  - **test_utils**: Testing utilities for unit and integration tests

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

```text
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

## Why Singleton Pattern Instead of Axum State

In typical Axum applications, shared resources (database pools, caches) are passed to handlers via the `State<T>` extractor. This library takes a different approach: it uses global static storage initialized by `init()`.

This design means:

- **For library users**: You don't need to manage state - just call `init().await?` and merge the router
- **Internally**: Any function can access configuration and database connections without threading state through every function argument

```rust,ignore
oauth2_passkey_axum::init().await?;

let app = Router::new()
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

This provides a simpler API at the cost of some flexibility. For a detailed comparison of both approaches and the trade-offs involved, see [Storage Pattern](../appendix/storage-pattern.md).

## Future Directions

- Further consolidation of related functionality
- Enhanced error handling and logging with standardization on thiserror
- Additional authentication methods
- Improved documentation and examples
