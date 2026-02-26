# Customizing Built-in Pages - Templates

This library provides built-in UI pages for login, account management, and administration:

- **Login** (`/o2p/user/login`) - Sign in and account creation
- **Account** (`/o2p/user/account`) - User account management
- **Admin List** (`/o2p/admin/index`) - User list for administrators
- **Admin User** (`/o2p/admin/user/{id}`) - User detail view for administrators

You can customize these pages in two ways:

| Method | Effort | When to Use |
| ------ | ------ | ----------- |
| [Built-in Themes](themes.md) | None | Pick a pre-built theme |
| [CSS](customizing-css.md) | Low | Change colors, fonts, spacing |
| **Templates** (this page) | High | Replace page structure entirely |

## Overview

This page explains how to create custom pages to replace the built-in UI. The process involves:

1. Creating your custom pages (handlers + templates)
2. Disabling the built-in UI via feature flags

See [Disabling Built-in UI](#disabling-built-in-ui) for feature flag configuration.

## Custom Login Page

By default, the `AuthUser` extractor redirects unauthenticated users to the built-in login page at `/o2p/user/login`.

To use your own custom login page:

1. Set `O2P_LOGIN_URL` environment variable to your page URL
2. Create your login page with the JavaScript APIs

```
┌─────────────────────────────────────────────────────────────┐
│  User visits /protected                                     │
│         ↓                                                   │
│  AuthUser extractor checks session                          │
│         ↓                                                   │
│  Not authenticated -> Redirect to O2P_LOGIN_URL             │
│         ↓                                                   │
│  Your custom login page (/login)                            │
│         ↓                                                   │
│  User clicks login button -> JavaScript API handles auth    │
│         ↓                                                   │
│  Success -> Redirect back to original page                  │
└─────────────────────────────────────────────────────────────┘
```

### 1. Set Environment Variable

```bash
# .env
O2P_LOGIN_URL='/login'
```

### 2. Create Login Handler

```rust,ignore
use askama::Template;
use axum::{response::{Html, IntoResponse, Redirect}, http::StatusCode};
use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX};

#[derive(Template)]
#[template(path = "login.j2")]
struct LoginTemplate<'a> {
    o2p_route_prefix: &'a str,
}

async fn login(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(_) => Redirect::to("/").into_response(),
        None => {
            let template = LoginTemplate {
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            Html(template.render().unwrap()).into_response()
        }
    }
}
```

### 3. Create Login Template

```html
<!-- templates/login.j2 -->
<!DOCTYPE html>
<html>
<head>
    <script>
        const O2P_ROUTE_PREFIX = '{{o2p_route_prefix}}';
    </script>
    <script src="{{o2p_route_prefix}}/oauth2/oauth2.js"></script>
    <script src="{{o2p_route_prefix}}/passkey/passkey.js"></script>
</head>
<body>
    <h1>Login</h1>

    <!-- Sign In -->
    <button onclick="oauth2.openPopup('login')">Sign in with Google</button>
    <button onclick="startAuthentication()">Sign in with Passkey</button>

    <!-- Create Account -->
    <button onclick="oauth2.openPopup('create_user')">Create account with Google</button>
    <button onclick="showRegistrationModal('create_user')">Create account with Passkey</button>
</body>
</html>
```

### 4. Register Route

```rust,ignore
let app = Router::new()
    .route("/login", get(login))
    .route("/protected", get(protected))
    .merge(oauth2_passkey_full_router());
```

## Custom Account Page

The library provides a built-in account management page at `/o2p/user/account`, but you can create your own.

### 1. Create Summary Handler

```rust,ignore
use oauth2_passkey_axum::{
    AuthUser, O2P_ROUTE_PREFIX, OAuth2Account, PasskeyCredential,
    UserId, list_accounts_core, list_credentials_core,
};

#[derive(Template)]
#[template(path = "summary.j2")]
struct SummaryTemplate {
    user_account: String,
    user_label: String,
    passkeys: Vec<PasskeyInfo>,
    oauth2_accounts: Vec<OAuth2Info>,
}

async fn summary(user: AuthUser) -> impl IntoResponse {
    let user_id = UserId::new(user.id.clone()).expect("Invalid user ID");

    // Fetch passkey credentials
    let passkeys = list_credentials_core(user_id.clone()).await
        .unwrap_or_default()
        .iter()
        .map(|c| PasskeyInfo {
            name: c.user.name.clone(),
            created_at: c.created_at.format("%Y-%m-%d").to_string(),
        })
        .collect();

    // Fetch OAuth2 accounts
    let oauth2_accounts = list_accounts_core(user_id).await
        .unwrap_or_default()
        .iter()
        .map(|a| OAuth2Info {
            provider: a.provider.clone(),
            email: a.email.clone(),
        })
        .collect();

    let template = SummaryTemplate {
        user_account: user.account,
        user_label: user.label,
        passkeys,
        oauth2_accounts,
    };
    Html(template.render().unwrap())
}
```

### 2. Create Summary Template

```html
<!-- templates/summary.j2 -->
<!DOCTYPE html>
<html>
<body>
    <h1>User Summary</h1>

    <h2>Account</h2>
    <p>{{user_account}} ({{user_label}})</p>

    <h2>Passkeys</h2>
    {% for passkey in passkeys %}
    <div>{{passkey.name}} - {{passkey.created_at}}</div>
    {% endfor %}

    <h2>OAuth2 Accounts</h2>
    {% for account in oauth2_accounts %}
    <div>{{account.provider}}: {{account.email}}</div>
    {% endfor %}
</body>
</html>
```

### 3. Register Route

```rust,ignore
let app = Router::new()
    .route("/summary", get(summary))
    .merge(oauth2_passkey_full_router());
```

## Custom Admin Page

The library provides a built-in admin interface at `/o2p/admin/index` for managing users.

### Disabling Built-in Admin UI

To disable the built-in admin UI and create your own:

```toml
# Cargo.toml
[dependencies]
oauth2-passkey-axum = { version = "0.3", default-features = false, features = ["user-ui"] }
```

### Admin Privilege Check

The first registered user (sequence_number = 1) is automatically an admin. Other users can be granted admin status. Check admin privileges using `has_admin_privileges()`:

```rust,ignore
async fn admin_guard(user: AuthUser) -> Result<(), StatusCode> {
    if !user.has_admin_privileges() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}
```

### 1. Create Admin List Handler

```rust,ignore
use oauth2_passkey_axum::{
    AuthUser, DbUser, SessionId, get_all_users,
};

#[derive(Template)]
#[template(path = "admin_list.j2")]
struct AdminListTemplate {
    users: Vec<UserInfo>,
}

async fn admin_list(user: AuthUser) -> Result<impl IntoResponse, StatusCode> {
    // Check admin privileges
    if !user.has_admin_privileges() {
        return Err(StatusCode::FORBIDDEN);
    }

    // Fetch all users
    let session_id = SessionId::new(user.session_id.clone())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let users = get_all_users(session_id).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .iter()
        .map(|u| UserInfo {
            id: u.id.clone(),
            account: u.account.clone(),
            label: u.label.clone(),
            is_admin: u.has_admin_privileges(),
        })
        .collect();

    let template = AdminListTemplate { users };
    Ok(Html(template.render().unwrap()))
}
```

### 2. Create Admin List Template

```html
<!-- templates/admin_list.j2 -->
<!DOCTYPE html>
<html>
<body>
    <h1>User Management</h1>
    <table>
        <tr>
            <th>Account</th>
            <th>Label</th>
            <th>Admin</th>
            <th>Actions</th>
        </tr>
        {% for user in users %}
        <tr>
            <td>{{user.account}}</td>
            <td>{{user.label}}</td>
            <td>{{user.is_admin}}</td>
            <td><a href="/admin/user/{{user.id}}">View</a></td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
```

### 3. Register Admin Routes

```rust,ignore
let app = Router::new()
    .route("/admin/users", get(admin_list))
    .route("/admin/user/:id", get(admin_user_detail))
    .merge(oauth2_passkey_full_router());
```

### Admin API Functions

The library exports functions for admin operations. All require admin privileges.

| Function | Description |
|----------|-------------|
| `get_all_users(session_id)` | Fetch all users |
| `get_user(session_id, user_id)` | Fetch a specific user |
| `update_user_admin_status(session_id, user_id, is_admin)` | Grant/revoke admin status |
| `delete_user_account_admin(session_id, user_id)` | Delete a user account |
| `delete_passkey_credential_admin(session_id, credential_id)` | Delete a passkey credential |
| `delete_oauth2_account_admin(session_id, provider_user_id)` | Unlink an OAuth2 account |

```rust,ignore
use oauth2_passkey_axum::{
    SessionId, UserId, CredentialId, ProviderUserId,
    get_all_users, get_user, update_user_admin_status,
    delete_user_account_admin, delete_passkey_credential_admin,
    delete_oauth2_account_admin,
};

// Example: Toggle admin status
async fn toggle_admin(user: AuthUser, target_user_id: &str) -> Result<(), String> {
    let session_id = SessionId::new(user.session_id).map_err(|e| e.to_string())?;
    let user_id = UserId::new(target_user_id.to_string()).map_err(|e| e.to_string())?;

    // Get current status
    let target = get_user(session_id.clone(), user_id.clone()).await
        .map_err(|e| e.to_string())?
        .ok_or("User not found")?;

    // Toggle (first user cannot be changed)
    update_user_admin_status(session_id, user_id, !target.is_admin).await
        .map_err(|e| e.to_string())?;

    Ok(())
}
```

> **Note**: The first user (sequence_number = 1) cannot have their admin status changed for security reasons.

## JavaScript API

### Authentication

| Function | Description |
|----------|-------------|
| `oauth2.openPopup('login')` | Sign in with OAuth2 |
| `oauth2.openPopup('create_user')` | Create account with OAuth2 |
| `startAuthentication()` | Sign in with passkey |
| `showRegistrationModal('create_user')` | Create account with passkey |

### Account Linking (from summary page)

| Function | Description |
|----------|-------------|
| `oauth2.openPopup('add_to_user')` | Link OAuth2 account to current user |
| `showRegistrationModal('add_to_user')` | Add passkey to current user |

## REST API for Account Management

All endpoints require CSRF token in `X-CSRF-Token` header.

### User Profile

```javascript
// Update account/label
fetch(`${O2P_ROUTE_PREFIX}/user/update`, {
    method: 'PUT',
    headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id, account, label })
});

// Delete account (removes all linked credentials)
fetch(`${O2P_ROUTE_PREFIX}/user/delete`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id })
});
```

### Passkey Credentials

```javascript
// Delete passkey
fetch(`${O2P_ROUTE_PREFIX}/passkey/credentials/${credentialId}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken }
});
```

### OAuth2 Accounts

```javascript
// Unlink OAuth2 account
fetch(`${O2P_ROUTE_PREFIX}/oauth2/accounts/${provider}/${providerUserId}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrfToken }
});
```

## Logout

```javascript
window.location.href = O2P_ROUTE_PREFIX + "/user/logout?redirect=/";
```

## Working Example

See `demo-custom-login` for a complete working example with styled templates.

```
demo-custom-login/
├── src/
│   └── main.rs          # Routes and handlers
├── templates/
│   ├── login.j2         # Custom login page
│   ├── summary.j2       # Custom summary page
│   ├── index_anon.j2    # Index for anonymous users
│   ├── index_user.j2    # Index for authenticated users
│   └── protected.j2     # Protected page
└── Cargo.toml
```

```bash
cd demo-custom-login
cp ../dot.env.example .env
# Add: O2P_LOGIN_URL='/login'
cargo run
# Open http://localhost:3001
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `O2P_LOGIN_URL` | `/o2p/user/login` | Redirect destination for unauthenticated users |
| `O2P_ADMIN_URL` | `/o2p/admin/index` | Admin panel URL (used in summary page) |
| `O2P_ROUTE_PREFIX` | `/o2p` | Prefix for all auth endpoints |

> **Note**: `O2P_LOGIN_URL` is **required** for custom login pages to work. Although it doesn't appear in your application code, the library reads it internally to determine where to redirect unauthenticated users.

## Disabling Built-in UI

After creating your custom pages, disable the corresponding built-in UI to avoid shipping unused code.

The library provides three feature flags:

| Feature | Default | Controls |
| ------- | ------- | -------- |
| `login-ui` | ON | Login page (`/user/login`) |
| `user-ui` | ON | Account management page (`/user/account`) |
| `admin-ui` | ON | Admin pages (`/admin/index`, `/admin/user/{id}`) |

Configure these in your `Cargo.toml` based on which pages you're replacing:

```toml
# Replace ALL pages with custom templates (recommended for full customization)
oauth2-passkey-axum = { version = "0.3", default-features = false }

# Custom login page only, keep built-in account management and admin UI
oauth2-passkey-axum = { version = "0.3", default-features = false, features = ["user-ui", "admin-ui"] }

# Replace only admin pages, keep built-in login and account management
oauth2-passkey-axum = { version = "0.3", default-features = false, features = ["login-ui", "user-ui"] }

# Replace only user pages, keep built-in login and admin
oauth2-passkey-axum = { version = "0.3", default-features = false, features = ["login-ui", "admin-ui"] }
```

**Note:** API endpoints (logout, delete account, admin operations, etc.) are always available regardless of feature flags. Only the HTML pages and their static assets are affected.

See [demo-custom-login](https://github.com/ktaka-ccmp/oauth2-passkey/tree/master/demo-custom-login) for a complete example with `default-features = false`.
