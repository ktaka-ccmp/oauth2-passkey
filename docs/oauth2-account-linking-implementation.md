# OAuth2 Account Linking Implementation Guide

This guide explains how to implement OAuth2 account linking functionality in your application using the `oauth2-passkey` library.

## Overview

OAuth2 account linking allows users to connect multiple OAuth2/OpenID Connect accounts (like Google, GitHub, etc.) to a single user account in your application. This is useful for:

- Allowing users to sign in with different OAuth2 providers
- Consolidating multiple accounts under one user identity
- Providing flexibility in authentication methods

## Prerequisites

- User must have an active session (already authenticated)
- OAuth2 provider must be configured in your application
- Understanding of the oauth2-passkey library session management

## Implementation Steps

### 1. Get User's CSRF Token

First, you need to retrieve the CSRF token from the user's active session. The library provides an endpoint for this:

```rust
// In your Axum handler
async fn get_csrf_token(auth_user: AuthUser) -> Result<Json<Value>, (StatusCode, String)> {
    Ok(Json(json!({
        "csrf_token": auth_user.csrf_token
    })))
}
```

### 2. Generate Page Session Token

Use the CSRF token to generate a page session token that will be used for session boundary protection:

```rust
use oauth2_passkey::generate_page_session_token;

// Generate page session token from CSRF token
let page_session_token = generate_page_session_token(&csrf_token);
```

### 3. Client-Side Implementation

#### HTML Template (using Jinja2/Askama)

```html
<!-- Add OAuth2 Account Button -->
<button onclick="linkOAuth2Account()">Add New OAuth2 Account</button>

<script>
    // Page session token for session boundary protection (from server)
    const PAGE_SESSION_TOKEN = "{{ page_session_token }}";

    function linkOAuth2Account() {
        // Open OAuth2 popup with add_to_user mode and page session token
        const oauth2Url = `/auth/oauth2/google/start?mode=add_to_user&context=${PAGE_SESSION_TOKEN}`;

        // Open in popup window
        const popup = window.open(
            oauth2Url,
            'oauth2_popup',
            'width=500,height=600,scrollbars=yes,resizable=yes'
        );

        // Listen for popup completion
        const checkClosed = setInterval(() => {
            if (popup.closed) {
                clearInterval(checkClosed);
                // Refresh page or update UI to show new linked account
                location.reload();
            }
        }, 1000);
    }
</script>
```

#### JavaScript Module Approach

```javascript
// oauth2-linking.js
class OAuth2AccountLinker {
    constructor(pageSessionToken, routePrefix = '') {
        this.pageSessionToken = pageSessionToken;
        this.routePrefix = routePrefix;
    }

    /**
     * Link a new OAuth2 account to the current user
     * @param {string} provider - OAuth2 provider (e.g., 'google', 'github')
     */
    linkAccount(provider) {
        const oauth2Url = `${this.routePrefix}/auth/oauth2/${provider}/start?mode=add_to_user&context=${this.pageSessionToken}`;

        return new Promise((resolve, reject) => {
            const popup = window.open(
                oauth2Url,
                'oauth2_linking_popup',
                'width=500,height=600,scrollbars=yes,resizable=yes'
            );

            if (!popup) {
                reject(new Error('Popup blocked'));
                return;
            }

            // Monitor popup for completion
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    resolve();
                }
            }, 1000);

            // Timeout after 5 minutes
            setTimeout(() => {
                clearInterval(checkClosed);
                if (!popup.closed) {
                    popup.close();
                }
                reject(new Error('OAuth2 linking timeout'));
            }, 300000);
        });
    }
}

// Usage
const linker = new OAuth2AccountLinker(PAGE_SESSION_TOKEN, '/auth');
linker.linkAccount('google')
    .then(() => {
        console.log('Account linked successfully');
        // Update UI or refresh page
        location.reload();
    })
    .catch(error => {
        console.error('Account linking failed:', error);
    });
```

### 4. Server-Side Handler Implementation

If you're not using the `oauth2_passkey_axum` crate, you'll need to implement the OAuth2 linking handler:

```rust
use oauth2_passkey::{
    coordination::oauth2::{oauth2_start_core, oauth2_callback_core},
    session::main::page_session_token::verify_page_session_token,
};

// OAuth2 start handler for account linking
async fn oauth2_start_linking(
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {

    // Check if this is an account linking request
    if params.get("mode") == Some(&"add_to_user".to_string()) {

        // Verify page session token for session boundary protection
        let context = params.get("context");
        if let Err(e) = verify_page_session_token(&headers, context).await {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid session context: {}", e)));
        }

        // Continue with OAuth2 flow in add_to_user mode
        match oauth2_start_core(&headers, Some("google"), Some("add_to_user"), context).await {
            Ok(redirect_url) => {
                Ok(Redirect::to(&redirect_url))
            }
            Err(e) => {
                Err((StatusCode::INTERNAL_SERVER_ERROR, format!("OAuth2 start failed: {}", e)))
            }
        }
    } else {
        // Handle regular OAuth2 registration/login
        // ... existing logic
    }
}
```

## Complete Example: User Settings Page

Here's a complete example showing how to implement OAuth2 account linking in a user settings page:

### Server-Side (Rust + Axum)

```rust
use askama::Template;
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{Html, Json},
    Extension,
};
use oauth2_passkey::{generate_page_session_token, list_accounts_core};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Template)]
#[template(path = "user_settings.html")]
struct UserSettingsTemplate {
    user: AuthUser,
    oauth2_accounts: Vec<OAuth2Account>,
    page_session_token: String,
}

async fn user_settings(auth_user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    // Generate page session token for OAuth2 linking
    let page_session_token = generate_page_session_token(&auth_user.csrf_token);

    // Get user's linked OAuth2 accounts
    let oauth2_accounts = list_accounts_core(&auth_user.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get accounts: {}", e)))?;

    let template = UserSettingsTemplate {
        user: auth_user,
        oauth2_accounts,
        page_session_token,
    };

    let html = template.render()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Template error: {}", e)))?;

    Ok(Html(html))
}

// CSRF token endpoint for client-side use
async fn get_csrf_token(auth_user: AuthUser) -> Json<Value> {
    Json(json!({
        "csrf_token": auth_user.csrf_token
    }))
}
```

### Template (user_settings.html)

```html
<!DOCTYPE html>
<html>
<head>
    <title>User Settings</title>
</head>
<body>
    <h1>User Settings</h1>

    <section>
        <h2>Linked OAuth2 Accounts</h2>

        {% if oauth2_accounts.is_empty() %}
            <p>No OAuth2 accounts linked yet.</p>
        {% else %}
            {% for account in oauth2_accounts %}
                <div class="account-item">
                    <strong>{{ account.provider }}</strong>: {{ account.email }}
                    <button onclick="unlinkAccount('{{ account.provider }}', '{{ account.provider_user_id }}')">
                        Unlink
                    </button>
                </div>
            {% endfor %}
        {% endif %}

        <button onclick="linkGoogleAccount()">Link Google Account</button>
    </section>

    <script>
        const PAGE_SESSION_TOKEN = "{{ page_session_token }}";

        function linkGoogleAccount() {
            const oauth2Url = `/auth/oauth2/google/start?mode=add_to_user&context=${PAGE_SESSION_TOKEN}`;

            const popup = window.open(
                oauth2Url,
                'google_linking',
                'width=500,height=600,scrollbars=yes,resizable=yes'
            );

            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    location.reload(); // Refresh to show new account
                }
            }, 1000);
        }

        function unlinkAccount(provider, providerUserId) {
            if (confirm(`Unlink ${provider} account?`)) {
                fetch(`/auth/oauth2/${provider}/unlink`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        provider_user_id: providerUserId
                    })
                })
                .then(() => location.reload())
                .catch(error => console.error('Unlink failed:', error));
            }
        }
    </script>
</body>
</html>
```

## Key Points to Remember

1. **Page Session Token**: Always generate and use a page session token for account linking to prevent session/page desynchronization attacks

2. **Session Verification**: The `verify_page_session_token()` function ensures that the OAuth2 linking request comes from the same user session

3. **Mode Parameter**: Use `mode=add_to_user` to indicate this is an account linking operation, not a new user registration

4. **Context Parameter**: Pass the page session token as the `context` parameter in the OAuth2 start URL

5. **Popup Window**: Use a popup window for OAuth2 linking to maintain the user's context on the main page

6. **Error Handling**: Always handle cases where popup is blocked, OAuth2 fails, or session is invalid

## Security Considerations

- **CSRF Protection**: The page session token prevents cross-site request forgery attacks
- **Session Validation**: Always verify the user has an active session before allowing account linking
- **Same-User Verification**: The page session token ensures the linking request comes from the authenticated user
- **Popup Security**: Popup windows prevent redirect-based attacks on the main application window

## Testing

When testing OAuth2 account linking, ensure you:

1. Test with multiple OAuth2 providers
2. Verify session persistence throughout the linking process
3. Test popup blocking scenarios
4. Validate error handling for invalid tokens
5. Confirm proper unlinking functionality

This implementation pattern provides secure, user-friendly OAuth2 account linking while maintaining proper session boundaries and security protections.