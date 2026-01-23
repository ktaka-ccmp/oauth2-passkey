# Custom Pages

Create fully custom login and summary pages with your own design.

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
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

## Custom Summary Page

The library provides a built-in summary page at `/o2p/user/summary`, but you can create your own.

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
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

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
# Open https://localhost:3443
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `O2P_LOGIN_URL` | `/o2p/user/login` | Redirect destination for unauthenticated users |
| `O2P_ROUTE_PREFIX` | `/o2p` | Prefix for all auth endpoints |
