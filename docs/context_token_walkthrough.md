# Session Boundary Protection with Page Context Tokens

This document explains how the page context token mechanism (based on obfuscated CSRF tokens) works to prevent session desynchronization issues in the authentication system.

## Overview

The system uses a dual approach to prevent session boundary issues:

1. **Explicit Registration Modes**
   - Explicit registration modes: `RegistrationMode::AddToUser` and `RegistrationMode::CreateUser`
   - Separate handlers for different authentication operations

2. **Page Context Tokens for Session/Page Synchronization**
   - Based on obfuscated CSRF tokens from the session
   - CSRF tokens are included in HTTP headers for state-changing operations
   - Obfuscated CSRF tokens are embedded in HTML/JavaScript as page context tokens
   - Integrated with session management for simplified implementation

## Implementation Details

### Page Context Token Mechanism

The page context token mechanism (based on CSRF tokens) serves two purposes:

1. Protecting against Cross-Site Request Forgery attacks
2. Preventing session boundary issues by verifying session continuity

When a session is created, a CSRF token is generated and stored with the session data. This token is:

- Required in the `X-CSRF-Token` header for all state-changing operations (POST, PUT, DELETE)
- Obfuscated and embedded in pages as `PAGE_CONTEXT_TOKEN` for session boundary verification

### Flow for Authentication and Adding a Passkey

1. **User Login**
   - When a user logs in (via OAuth2 or passkey), the system:
     - Creates a session cookie with a CSRF token
     - The obfuscated CSRF token is embedded in the page as `PAGE_CONTEXT_TOKEN`

2. **Adding a Passkey to an Existing User**
   - Client initiates passkey registration with `mode: 'add_to_user'`
   - Client submits the passkey data with the CSRF token in the header
   - Client may include the page context token (obfuscated CSRF token) for additional verification
   - Server verifies that:
     - The CSRF token in the header matches the token in the session
     - If provided, the page context token matches the obfuscated CSRF token
   - If verification passes, the passkey is associated with the user
   - If verification fails (e.g., user session changed), an error is returned

3. **Creating a New User with a Passkey**
   - Client initiates passkey registration with `mode: 'create_user'`
   - Client submits the passkey data to the server
   - Server creates a new user account with the passkey
   - Server sets a new session cookie with a CSRF token for the new user

### Implementation in Code

The page context token functionality is implemented across several files:

- `session.rs` - Handles CSRF token verification for all state-changing operations
- `context_token.rs` - Contains the `obfuscate_token` function for obfuscating CSRF tokens
- `verify_context_token` - Verifies that the page context token matches the obfuscated CSRF token

## Security Considerations

- CSRF tokens are required for all state-changing operations
- Tokens are verified against the session data to ensure session continuity
- The obfuscated CSRF token is used as a page context token to prevent session boundary issues
- HMAC-SHA256 is used for token obfuscation to prevent direct exposure
- The server secret is configurable via the `AUTH_SERVER_SECRET` environment variable

## Testing

You can test the session boundary protection by:

1. Logging in as User A
2. Opening a new passkey registration page
3. In a different tab or browser, logging out and logging in as User B
4. Returning to the registration page and attempting to complete registration
5. The system should reject the operation because:
   - The CSRF token in the header won't match User B's session
   - The page context token (obfuscated CSRF token) won't match User B's session

This protection mechanism helps prevent confused deputy problems and session desynchronization issues in multi-tab or shared browser scenarios.
