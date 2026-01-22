# OAuth2 User and Session Verification in the Authentication Flow
## Overview
This document details the user and session verification mechanisms within the OAuth2 authentication flow. It outlines the security measures implemented at each critical stage, from pre-redirect initiation to post-redirect callback processing, to ensure robust identity confirmation and maintain session integrity.
## Current Verification Mechanism
### Before OAuth2 Redirect (Initiation)
1. **Page Session Token Verification**
   - When adding an OAuth2 account to an existing user, the system verifies:
     - That the user has a valid session
     - That the page session token matches the obfuscated CSRF token from the session
   - This verification occurs **before** redirecting to the OAuth2 provider's endpoint
   - Ensures the user who loaded the page is the same user making the request
2. **State Parameter and Session Preservation**
   - A state parameter containing several security components is generated:
     - CSRF ID for flow integrity (references a secret token stored server-side)
     - Nonce for ID token verification
     - PKCE for code exchange
     - Session reference (`misc_id`) that points to the original session ID
   - The current session ID is stored in cache with a reference ID (`misc_id`)
   - This enables session continuity throughout the OAuth2 flow
   - The state parameter is included in the redirect URL to the OAuth2 provider
### After OAuth2 Redirect (Callback)
1. **Callback Handling**
   - State parameter is extracted and decoded from the callback
   - CSRF protection works as follows for both redirect and form_post modes:
     - CSRF ID is extracted from the state parameter
     - CSRF token is retrieved from the cookie
     - The stored token associated with the CSRF ID is fetched
     - Cookie token is compared with the stored token
     - SameSite cookie attribute is set based on response mode (None for form_post, Lax for query)
   - Original user context is retrieved using the session reference in state parameter:
     ```rust
     // Decode state to access misc_id (session reference)
     let state_in_response = decode_state(&query.state);
     // Retrieve the original user context from when the flow started
     let state_user = get_uid_from_stored_session_by_state_param(&state_in_response).await?;
     ```
   - This mechanism works for both redirect-based and form post response modes
   - OAuth2 account is processed based on the original user context
2. **Account Linking Logic**
   - Handles multiple scenarios:
     - User logged in, OAuth2 account exists
     - User logged in, OAuth2 account doesn't exist
     - User not logged in, OAuth2 account exists
     - User not logged in, OAuth2 account doesn't exist
3. **Session Renewal**
   - Creates a completely new session for the user after authentication
   - Generates fresh session cookies with new CSRF tokens
   - Mitigates session fixation attacks
   - Invalidates any previously captured credentials
## Security Measures
The system implements multiple layers of security:
1. **Page Session Token Verification**
   - Verifies user identity before initiating the OAuth2 flow
   - Prevents unauthorized account linking attempts
   - Ensures session continuity between page load and action
   - Uses obfuscated CSRF tokens as page session tokens
2. **State Parameter as Multi-Purpose Security Container**
   - Contains multiple security components:
     - CSRF ID for flow integrity verification (references a secret token)
     - Session reference (`misc_id`) for user context preservation
     - Additional parameters for OAuth2 protocol security (nonce, PKCE)
   - Original session ID stored server-side via `misc_session` mechanism
   - Single-use state parameter verified during callback
   - Creates secure binding between initial request and callback
3. **Multi-Layered Protection**
   - Page session token verification before flow initiation
   - State parameter with CSRF ID for redirect-based flow integrity
   - Session context preservation via `misc_session` mechanism for all flow types
   - These layers prevent cross-site request forgery and session desynchronization
4. **Complete Session Rotation**
   - New session created after successful authentication
   - Fresh credentials issued (session ID and page session token)
   - Ensures clean state after authentication
## Security Analysis
The current implementation follows OAuth 2.0 security best practices and provides robust protection:
1. **Pre-Authorization Verification**
   - Page session token verification ensures legitimate user before redirect
   - Prevents session desynchronization between page load and action initiation
2. **Session Continuity Through Flow**
   - Original session preserved via the `misc_session` mechanism
   - Ensures the OAuth2 account links to the user who initiated the flow
   - Works consistently across redirect-based and form post response modes
3. **Flow Integrity Verification**
   - State parameter with CSRF ID and cookie with CSRF token secure both redirect and form_post flows
   - Prevents tampering during redirects
   - Minimizes exposure of the secret token (only ID is passed to the Authorization Server)
   - Cookie SameSite attribute is automatically set based on response mode for optimal security
4. **Post-Authorization Session Renewal**
   - Complete session rotation after authentication
   - Mitigates session fixation and hijacking attempts
## Conclusion
The implemented security measures provide strong protection against common OAuth 2.0 vulnerabilities:
- Session fixation attacks
- Cross-site request forgery
- Session hijacking
- Unauthorized account linking
The system uses a combination of CSRF protection, state parameters, response mode validation, and session renewal to create a secure authentication flow without unnecessary complexity or dependencies, aligning with the project's goals of simplicity and security.
## Note on CSRF Tokens in the System
It's important to understand that there are distinct CSRF protection mechanisms in different parts of the system:
1. **OAuth2 Flow CSRF Protection**
   - Implemented in `oauth2/main/core.rs`
   - Uses a double-submit pattern with:
     - CSRF ID stored in the state parameter
     - CSRF token stored in a cookie
     - Token verification during callback
   - Applied to both redirect and form_post response modes
   - Cookie SameSite attribute is automatically set based on response mode:
     - SameSite=None for form_post mode (required for cross-site POST requests)
     - SameSite=Lax for query mode (more secure for redirect-based flows)
   - HTTP method is strictly enforced based on response mode:
     - Only POST requests allowed for form_post mode
     - Only GET requests allowed for query mode
2. **Session CSRF Protection**
   - Implemented in `session/main/session.rs`
   - Used for general API endpoint protection
   - Stored as part of the user session
   - Verified via X-CSRF-Token header in requests
   - Used throughout the application for non-OAuth2 endpoints
3. **Page Session Token**
   - An obfuscated version of the session CSRF token
   - Used to verify that the user who loaded a page is the same one making a subsequent request
   - Implemented as a query parameter for certain actions
These mechanisms work together but serve different purposes in the security architecture of the system.
