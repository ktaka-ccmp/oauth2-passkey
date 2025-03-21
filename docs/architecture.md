# Architecture blueprint

## Overview

The following is a blueprint of the architecture of this application. It reflects the current state of the application as of March 2025.

## Current Components

- **demo-integrated**: Example Axum application that uses OAuth2 and passkey authentication
- **libaxum**: Provides OAuth2 and passkey authentication handlers for Axum applications
  - Includes routers for OAuth2, passkey, and user summary endpoints
  - Handles HTTP-specific concerns like request/response handling
- **oauth2_passkey**: Core authentication coordination library
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
  - Handles session cookies and context tokens
  - Provides user information from sessions

- **storage**: Provides data persistence
  - Implements cache storage for temporary data
  - Provides SQL database access for persistent data
  - Supports both PostgreSQL and SQLite

- **userdb**: Manages user accounts
  - Creates and updates user records
  - Provides user lookup functionality
  - Links authentication methods to user accounts

### libaxum (Axum Integration)

- Provides Axum-specific HTTP handlers and routers
- Translates between HTTP requests/responses and core library functions
- Manages authentication middleware for Axum applications

## Data Flow

1. HTTP requests are received by the Axum application
2. libaxum handlers process the requests and call oauth2_passkey functions
3. The coordination layer orchestrates the authentication flow
4. Specific modules (oauth2, passkey, session) handle their respective operations
5. User data is stored and retrieved through the storage layer
6. Responses are returned through libaxum to the client

## Security Considerations

- Session tokens are securely managed with proper expiration
- Context tokens provide protection against session desynchronization
- Passkey credentials follow WebAuthn security standards
- OAuth2 implementation follows best practices for authorization flow

## Dependency Structure

The dependencies between components are implemented as follows:

- libaxum depends on oauth2_passkey
- oauth2_passkey depends on its internal modules (oauth2, passkey, session, storage, userdb)
- oauth2 and passkey depend on storage but not on each other
- userdb depends on storage but not on oauth2 or passkey

## Future Directions

- Further consolidation of related functionality
- Enhanced error handling and logging with standardization on thiserror
- Additional authentication methods
- Improved documentation and examples
