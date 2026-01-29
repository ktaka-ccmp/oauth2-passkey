# Chapter 7: Passkey/WebAuthn Implementation

This chapter provides a practical guide to implementing WebAuthn/Passkey authentication using the oauth2-passkey library. It covers both client-side JavaScript implementation and server-side Rust handlers.

## Overview

WebAuthn (Web Authentication) is a W3C standard that enables passwordless authentication using cryptographic credentials called passkeys. Passkeys can be stored on:

- **Platform authenticators**: Built-in device security (Windows Hello, Apple Touch ID/Face ID, Android fingerprint)
- **Roaming authenticators**: Hardware security keys (YubiKey, Google Titan)
- **Cross-device passkeys**: Synced across devices via password managers or platform accounts

### Key Security Benefits

1. **Phishing-resistant**: Credentials are bound to the origin domain
2. **No shared secrets**: Private keys never leave the authenticator
3. **Replay attack prevention**: Signature counters prevent credential cloning
4. **User verification**: Optional biometric or PIN verification

## Architecture Overview

The passkey implementation follows a layered architecture:

```
+---------------------------+
|   Client (Browser/JS)     |
+---------------------------+
            |
            v
+---------------------------+
|  oauth2_passkey_axum      |  <-- HTTP handlers
+---------------------------+
            |
            v
+---------------------------+
|  oauth2_passkey           |
|  (coordination layer)     |  <-- Business logic
+---------------------------+
            |
            v
+---------------------------+
|  passkey module           |  <-- Core WebAuthn logic
|  (register/auth flows)    |
+---------------------------+
            |
            v
+---------------------------+
|  Storage layer            |  <-- SQLite/PostgreSQL
|  (PasskeyStore)           |
+---------------------------+
```

## Registration Flow

The registration flow creates a new passkey credential and associates it with a user account.

### Flow Diagram

```
Client                    Server                      Authenticator
  |                          |                              |
  |-- POST /register/start ->|                              |
  |                          |-- Generate challenge --------|
  |                          |-- Store options in cache ----|
  |<- RegistrationOptions ---|                              |
  |                          |                              |
  |-- navigator.credentials.create() -------------------->  |
  |                          |                              |-- Create keypair
  |                          |                              |-- Sign challenge
  |<------------------------- Credential ------------------|
  |                          |                              |
  |-- POST /register/finish ->|                             |
  |                          |-- Validate challenge --------|
  |                          |-- Verify attestation --------|
  |                          |-- Store credential ----------|
  |<- Success + Session -----|                              |
```

### Step 1: Start Registration

The client requests registration options from the server.

**Endpoint**: `POST /passkey/register/start`

**Request Body**:
```json
{
  "username": "user@example.com",
  "displayname": "John Doe",
  "mode": "create_user"
}
```

The `mode` field specifies the registration intent:
- `create_user`: Creating a new user account with a passkey
- `add_to_user`: Adding a passkey to an existing authenticated user

**Server Response** (`RegistrationOptions`):
```json
{
  "challenge": "base64url-encoded-random-bytes",
  "rpId": "example.com",
  "rp": {
    "name": "Example App",
    "id": "example.com"
  },
  "user": {
    "user_handle": "random-user-handle",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "residentKey": "required",
    "requireResidentKey": true,
    "userVerification": "discouraged"
  },
  "timeout": 60000,
  "attestation": "direct"
}
```

### Step 2: Browser Creates Credential

The browser's WebAuthn API creates the credential using the authenticator.

```javascript
// Convert base64url challenge to Uint8Array
options.challenge = base64URLToUint8Array(options.challenge);
options.user.id = base64URLToUint8Array(options.user.user_handle);

const credential = await navigator.credentials.create({
    publicKey: options
});
```

### Step 3: Finish Registration

The client sends the created credential to the server for verification and storage.

**Endpoint**: `POST /passkey/register/finish`

**Request Body** (`RegisterCredential`):
```json
{
  "id": "credential-id",
  "raw_id": "base64url-encoded-raw-id",
  "type": "public-key",
  "response": {
    "attestation_object": "base64url-encoded-attestation",
    "client_data_json": "base64url-encoded-client-data"
  },
  "user_handle": "user-handle-from-options"
}
```

The server performs these validations:
1. Decode and verify `clientDataJSON` (type, challenge, origin)
2. Parse and verify attestation object
3. Extract and store the public key
4. Create user account (for `create_user` mode)
5. Store the credential in the database

## Authentication Flow

The authentication flow verifies a user's identity using their registered passkey.

### Flow Diagram

```
Client                    Server                      Authenticator
  |                          |                              |
  |-- POST /auth/start ----->|                              |
  |                          |-- Generate challenge --------|
  |                          |-- Store challenge in cache --|
  |<- AuthenticationOptions -|                              |
  |                          |                              |
  |-- navigator.credentials.get() ----------------------->  |
  |                          |                              |-- Find credential
  |                          |                              |-- Sign challenge
  |<------------------------- Assertion -------------------|
  |                          |                              |
  |-- POST /auth/finish ---->|                              |
  |                          |-- Validate challenge --------|
  |                          |-- Verify signature ----------|
  |                          |-- Update counter ------------|
  |<- Success + Session -----|                              |
```

### Step 1: Start Authentication

The client requests authentication options.

**Endpoint**: `POST /passkey/auth/start`

**Request Body** (optional username for non-discoverable credentials):
```json
{
  "username": "user@example.com"
}
```

Or empty body `{}` for discoverable credentials.

**Server Response** (`AuthenticationOptions`):
```json
{
  "challenge": "base64url-encoded-random-bytes",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [],
  "userVerification": "discouraged",
  "authId": "unique-auth-session-id"
}
```

### Step 2: Browser Gets Assertion

```javascript
options.challenge = base64URLToUint8Array(options.challenge);

const credential = await navigator.credentials.get({
    publicKey: options
});
```

### Step 3: Finish Authentication

**Endpoint**: `POST /passkey/auth/finish`

**Request Body** (`AuthenticatorResponse`):
```json
{
  "id": "credential-id",
  "raw_id": "base64url-encoded-raw-id",
  "auth_id": "auth-session-id-from-options",
  "response": {
    "authenticator_data": "base64url-encoded-auth-data",
    "client_data_json": "base64url-encoded-client-data",
    "signature": "base64url-encoded-signature",
    "user_handle": "base64url-encoded-user-handle"
  }
}
```

The server performs these verifications:
1. Validate the challenge matches the stored challenge
2. Verify client data (type, origin, challenge)
3. Verify authenticator data (RP ID hash, flags)
4. Verify the signature using the stored public key
5. Check and update the signature counter
6. Create a session for the authenticated user

## Credential Management

### Listing Credentials

Authenticated users can list their registered passkey credentials.

**Endpoint**: `GET /passkey/credentials`

**Response**:
```json
[
  {
    "credential_id": "abc123...",
    "user_id": "user-uuid",
    "public_key": "base64url-encoded-key",
    "aaguid": "authenticator-aaguid",
    "counter": 5,
    "user": {
      "user_handle": "handle",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z",
    "last_used_at": "2024-01-15T12:00:00Z"
  }
]
```

### Updating Credentials

Users can update the name and display name of their credentials.

**Endpoint**: `POST /passkey/credential/update`

**Request Body**:
```json
{
  "credential_id": "abc123...",
  "name": "New Name",
  "display_name": "New Display Name"
}
```

### Deleting Credentials

Users can delete their own passkey credentials.

**Endpoint**: `DELETE /passkey/credentials/{credential_id}`

**Response**: `204 No Content` on success

## Client-Side Implementation

### Base64URL Utilities

WebAuthn uses base64url encoding. These utility functions handle the conversion:

```javascript
function arrayBufferToBase64URL(buffer) {
    if (!buffer) return null;
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (const byte of bytes) {
        str += String.fromCharCode(byte);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLToUint8Array(base64URL) {
    if (!base64URL) return null;
    const padding = '='.repeat((4 - base64URL.length % 4) % 4);
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}
```

### Complete Registration Example

```javascript
async function startRegistration(mode, username, displayname) {
    try {
        // Step 1: Get registration options from server
        const startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/start', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                username: username,
                displayname: displayname,
                mode: mode  // 'create_user' or 'add_to_user'
            })
        });

        if (!startResponse.ok) {
            throw new Error('Failed to start registration');
        }

        const options = await startResponse.json();

        // Step 2: Convert base64url to ArrayBuffer
        let userHandle = options.user.user_handle;
        options.challenge = base64URLToUint8Array(options.challenge);
        options.user.id = base64URLToUint8Array(userHandle);

        // Step 3: Create credential using WebAuthn API
        const credential = await navigator.credentials.create({
            publicKey: options
        });

        // Step 4: Prepare response for server
        const credentialResponse = {
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                attestation_object: arrayBufferToBase64URL(
                    credential.response.attestationObject
                ),
                client_data_json: arrayBufferToBase64URL(
                    credential.response.clientDataJSON
                )
            },
            user_handle: userHandle,
            mode: mode
        };

        // Step 5: Send credential to server
        const finishResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/register/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin',
            body: JSON.stringify(credentialResponse)
        });

        if (finishResponse.ok) {
            location.reload();
        } else {
            throw new Error('Registration verification failed');
        }
    } catch (error) {
        console.error('Registration error:', error);
        alert('Registration failed: ' + error.message);
    }
}
```

### Complete Authentication Example

```javascript
async function startAuthentication() {
    try {
        // Step 1: Get authentication options from server
        const startResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}'
        });

        if (!startResponse.ok) {
            throw new Error('Failed to start authentication');
        }

        const options = await startResponse.json();

        // Step 2: Convert challenge to ArrayBuffer
        options.challenge = base64URLToUint8Array(options.challenge);

        // Step 3: Get credential using WebAuthn API
        const credential = await navigator.credentials.get({
            publicKey: options
        });

        // Step 4: Prepare response for server
        const authResponse = {
            auth_id: options.authId,
            id: credential.id,
            raw_id: arrayBufferToBase64URL(credential.rawId),
            type: credential.type,
            response: {
                authenticator_data: arrayBufferToBase64URL(
                    credential.response.authenticatorData
                ),
                client_data_json: arrayBufferToBase64URL(
                    credential.response.clientDataJSON
                ),
                signature: arrayBufferToBase64URL(credential.response.signature),
                user_handle: arrayBufferToBase64URL(credential.response.userHandle)
            }
        };

        // Step 5: Verify with server
        const verifyResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(authResponse)
        });

        if (verifyResponse.ok) {
            location.reload();
        } else {
            throw new Error('Authentication verification failed');
        }
    } catch (error) {
        console.error('Authentication error:', error);
        alert('Authentication failed: ' + error.message);
    }
}
```

### Conditional UI (Autofill)

Conditional UI allows passkeys to appear in the browser's autofill dropdown. This provides a seamless user experience.

```javascript
(async function() {
    // Feature detection
    if (!window.PublicKeyCredential) {
        console.error('WebAuthn not supported');
        return;
    }

    const available = await PublicKeyCredential.isConditionalMediationAvailable();
    if (!available) {
        console.error('Conditional UI not available');
        return;
    }

    // Get fresh challenge from server
    async function getFreshChallenge() {
        const response = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(null)
        });

        if (!response.ok) return null;
        return await response.json();
    }

    // Start credential request with conditional mediation
    async function startCredentialRequest(options) {
        const publicKeyOptions = {
            challenge: base64URLToUint8Array(options.challenge),
            rpId: options.rpId,
            timeout: options.timeout || 300000,
            userVerification: options.userVerification
        };

        try {
            const credential = await navigator.credentials.get({
                mediation: 'conditional',  // Enable autofill UI
                publicKey: publicKeyOptions
            });

            if (credential) {
                // Send to server for verification
                const authResponse = await fetch(O2P_ROUTE_PREFIX + '/passkey/auth/finish', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id: credential.id,
                        raw_id: arrayBufferToBase64URL(credential.rawId),
                        response: {
                            client_data_json: arrayBufferToBase64URL(
                                credential.response.clientDataJSON
                            ),
                            authenticator_data: arrayBufferToBase64URL(
                                credential.response.authenticatorData
                            ),
                            signature: arrayBufferToBase64URL(credential.response.signature),
                            user_handle: credential.response.userHandle
                                ? arrayBufferToBase64URL(credential.response.userHandle)
                                : null
                        },
                        type: credential.type,
                        auth_id: options.authId
                    })
                });

                if (authResponse.ok) {
                    window.location.href = '/';
                }
            }
        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error('Authentication error:', error);
            }
        }
    }

    // Initialize with fresh challenge
    const options = await getFreshChallenge();
    if (options) {
        startCredentialRequest(options);
    }
})();
```

## Server-Side Implementation

### Router Setup

The passkey routes are provided by the `oauth2_passkey_axum` crate:

```rust
use axum::Router;
use oauth2_passkey_axum::{oauth2_passkey_router, O2P_ROUTE_PREFIX};

let app = Router::new()
    .route("/", get(index))
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

### Route Structure

The passkey router provides these endpoints:

```
/passkey/
    /passkey.js          - Client-side JavaScript
    /conditional_ui      - Conditional UI HTML page
    /conditional_ui.js   - Conditional UI JavaScript
    /register/
        /start           - POST: Start registration
        /finish          - POST: Finish registration
    /auth/
        /start           - POST: Start authentication
        /finish          - POST: Finish authentication
    /credentials         - GET: List credentials
    /credentials/{id}    - DELETE: Delete credential
    /credential/update   - POST: Update credential
```

### Handler Implementation

The HTTP handlers delegate to coordination layer functions:

```rust
// Start registration handler
async fn handle_start_registration(
    auth_user: Option<AuthUser>,
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationOptions>, (StatusCode, String)> {
    let session_user = auth_user.as_ref().map(SessionUser::from);

    let registration_options = handle_start_registration_core(session_user.as_ref(), request)
        .await
        .into_response_error()?;

    Ok(Json(registration_options))
}

// Finish authentication handler
async fn handle_finish_authentication(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    let (_, name, headers) = handle_finish_authentication_core(auth_response)
        .await
        .into_response_error()?;

    Ok((headers, name))
}
```

### Well-Known Endpoint

WebAuthn supports related origins through a well-known endpoint. Mount it at the root:

```rust
use oauth2_passkey_axum::passkey_well_known_router;

let app = Router::new()
    .merge(passkey_well_known_router())  // Serves /.well-known/webauthn
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ORIGIN` | Required | Full origin URL (e.g., `https://example.com`) |
| `PASSKEY_RP_NAME` | Same as ORIGIN | Relying party display name |
| `PASSKEY_TIMEOUT` | `60` | WebAuthn operation timeout (seconds) |
| `PASSKEY_CHALLENGE_TIMEOUT` | `60` | Challenge validity period (seconds) |
| `PASSKEY_ATTESTATION` | `direct` | Attestation conveyance (`none`, `direct`, `indirect`, `enterprise`) |
| `PASSKEY_AUTHENTICATOR_ATTACHMENT` | `platform` | Authenticator type (`platform`, `cross-platform`, `None`) |
| `PASSKEY_RESIDENT_KEY` | `required` | Resident key requirement (`required`, `preferred`, `discouraged`) |
| `PASSKEY_REQUIRE_RESIDENT_KEY` | `true` | Require resident/discoverable credentials |
| `PASSKEY_USER_VERIFICATION` | `discouraged` | User verification (`required`, `preferred`, `discouraged`) |
| `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` | `false` | Use single user handle per user (set to `true` for unique per credential) |
| `PASSKEY_USER_ACCOUNT_FIELD` | `name` | Field to use for user account (`name` or `display_name`) |
| `PASSKEY_USER_LABEL_FIELD` | `display_name` | Field to use for user label (`name` or `display_name`) |

### Example Configuration

```env
ORIGIN=https://example.com
PASSKEY_RP_NAME="My Application"
PASSKEY_TIMEOUT=120
PASSKEY_ATTESTATION=direct
PASSKEY_AUTHENTICATOR_ATTACHMENT=platform
PASSKEY_RESIDENT_KEY=required
PASSKEY_USER_VERIFICATION=preferred
```

## Data Types

### PasskeyCredential

Stored credential information:

```rust
pub struct PasskeyCredential {
    /// Raw credential ID (base64url encoded)
    pub credential_id: String,
    /// User ID associated with this credential (database ID)
    pub user_id: String,
    /// Public key bytes (base64url encoded)
    pub public_key: String,
    /// AAGUID of the authenticator
    pub aaguid: String,
    /// Counter value for replay attack prevention
    pub counter: u32,
    /// User entity information
    pub user: PublicKeyCredentialUserEntity,
    /// Timestamp fields
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}
```

### Type-Safe Identifiers

The library uses type-safe wrappers for identifiers:

```rust
// Credential ID with validation
let credential_id = CredentialId::new("abc123...".to_string())?;

// User ID with validation
let user_id = UserId::new("user-uuid".to_string())?;

// Challenge types for cache operations
let challenge_type = ChallengeType::registration();
let challenge_type = ChallengeType::authentication();
```

## Security Considerations

### Challenge Validation

- Challenges are cryptographically random (32 bytes)
- Challenges are stored in cache with TTL
- Each challenge can only be used once
- Challenge verification includes origin check

### Attestation Verification

The library supports multiple attestation formats:
- `none`: No attestation
- `packed`: Standard attestation
- `tpm`: TPM-based attestation
- `u2f`: FIDO U2F attestation

### Counter Verification

Signature counters prevent credential cloning:
- Counter must increase with each authentication
- Counter of 0 indicates authenticator doesn't support counters
- Decreased counter triggers security warning

### User Handle Privacy

User handles are random identifiers that:
- Don't reveal user identity to authenticators
- Can be configured to be unique per credential
- Support multiple credentials per user

## Demo Application

A complete demo application is available in `demo-passkey/`:

```rust
use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX, oauth2_passkey_router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    // Load environment and initialize library
    dotenvy::dotenv().ok();
    oauth2_passkey_axum::init().await?;

    // Create router with passkey authentication
    let app = Router::new()
        .route("/", get(index))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    axum_server::bind(addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
```

### HTML Template Example

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Passkey Demo</title>
    <script>
        const O2P_ROUTE_PREFIX = '{{o2p_route_prefix}}';
    </script>
    <script src="{{o2p_route_prefix}}/passkey/passkey.js"></script>
</head>
<body>
    <h1>{{message}}</h1>

    <!-- For anonymous users -->
    <div id="passkey-auth">
        <button onclick="showRegistrationModal('create_user')">
            Register Passkey
        </button>
        <button onclick="startAuthentication()">
            Sign in
        </button>
    </div>
</body>
</html>
```

## Related Documentation

- [OAuth2 Implementation](./oauth2.md) - Google OAuth2 authentication
- [Framework Integration](./framework.md) - Axum framework integration
- [WebAuthn Compatibility](../compatibility/webauthn.md) - Browser compatibility
- [Security Guide](../security/csrf.md) - CSRF protection
