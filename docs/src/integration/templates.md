# Askama Templates with AuthUser

This guide explains how to use Askama templates with the `AuthUser` extractor in oauth2-passkey applications.

## Overview

[Askama](https://github.com/djc/askama) is a type-safe, compiled template engine for Rust that uses Jinja2-like syntax. When combined with oauth2-passkey, you can create dynamic HTML pages that display authenticated user information.

## Defining Template Structs

Template structs define the data available in your templates. Use the `#[derive(Template)]` macro and specify the template file path.

### Basic Template with Message

```rust,ignore
use askama::Template;

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}
```

### Template with AuthUser

To display authenticated user information, include `AuthUser` as a field:

```rust,ignore
use askama::Template;
use oauth2_passkey_axum::AuthUser;

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate<'a> {
    user: AuthUser,
    auth_route_prefix: &'a str,
}
```

## Passing O2P_ROUTE_PREFIX to Templates

The `O2P_ROUTE_PREFIX` constant contains the authentication route prefix (default: `/o2p`). Pass it to templates to construct authentication URLs correctly.

```rust,ignore
use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX};

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

// When creating the template:
let template = IndexTemplateUser {
    message: &message,
    auth_route_prefix: O2P_ROUTE_PREFIX.as_str(),
};
```

## Rendering Templates in Handlers

### Handler with Optional Authentication

Use `Option<AuthUser>` to handle both authenticated and anonymous users:

```rust,ignore
use askama::Template;
use axum::{http::StatusCode, response::Html};
use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX};

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
    auth_route_prefix: &'a str,
}

pub async fn index(user: Option<AuthUser>) -> Result<Html<String>, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.account);
            let template = IndexTemplateUser {
                message: &message,
                auth_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon {
                message: &message,
                auth_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            let html = Html(
                template
                    .render()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
            );
            Ok(html)
        }
    }
}
```

### Handler Requiring Authentication

Use `AuthUser` directly (not `Option`) to require authentication:

```rust,ignore
pub async fn protected(user: AuthUser) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate {
        user,
        auth_route_prefix: O2P_ROUTE_PREFIX.as_str(),
    };
    let html = Html(
        template
            .render()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?,
    );
    Ok(html)
}
```

## AuthUser Fields

The `AuthUser` struct provides the following fields for use in templates:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `String` | Unique user identifier |
| `account` | `String` | User's account name (email or username) |
| `label` | `String` | User's display name |
| `is_admin` | `bool` | Whether the user has admin privileges |
| `sequence_number` | `Option<i64>` | Database-assigned sequence number |
| `created_at` | `DateTime<Utc>` | When the account was created |
| `updated_at` | `DateTime<Utc>` | When the account was last updated |
| `csrf_token` | `String` | CSRF token for form submissions |

## Template Examples (Jinja2 Syntax)

### Displaying User Information

```html
<div class="user-info">
    <h2>Your Account Information:</h2>
    <table>
        <tr>
            <td>User ID</td>
            <td>{{ user.id }}</td>
        </tr>
        <tr>
            <td>Account</td>
            <td>{{ user.account }}</td>
        </tr>
        <tr>
            <td>Label</td>
            <td>{{ user.label }}</td>
        </tr>
        <tr>
            <td>Is Admin</td>
            <td>{{ user.is_admin }}</td>
        </tr>
        <tr>
            <td>Created At</td>
            <td>{{ user.created_at }}</td>
        </tr>
    </table>
</div>
```

### Handling Optional Fields

Use conditional syntax for `Option` types:

```html
<tr>
    <td>Sequence Number</td>
    <td>{% if user.sequence_number.is_some() %}{{ user.sequence_number.unwrap() }}{% else %}None{% endif %}</td>
</tr>
```

### Using auth_route_prefix for URLs

Include the route prefix in authentication-related URLs:

```html
<!-- Logout button -->
<button onclick="Logout()">Logout</button>
<script>
    function Logout() {
        window.location.href = "{{auth_route_prefix}}/user/logout?redirect=/";
    }
</script>

<!-- Include OAuth2 JavaScript -->
<script src="{{auth_route_prefix}}/oauth2/oauth2.js"></script>

<!-- Set prefix for JavaScript use -->
<script>
    const O2P_ROUTE_PREFIX = '{{auth_route_prefix}}';
</script>
```

### Login Buttons (Anonymous Users)

```html
<button onclick="oauth2.openPopup('create_user')">Create User</button>
<button onclick="oauth2.openPopup('login')">Login</button>
<button onclick="oauth2.openPopup('create_user_or_login')">Either way</button>

<script src="{{auth_route_prefix}}/oauth2/oauth2.js"></script>
<script>
    const O2P_ROUTE_PREFIX = '{{auth_route_prefix}}';
</script>
```

### Conditional Content Based on Admin Status

```html
{% if user.is_admin %}
<div class="admin-panel">
    <h3>Admin Controls</h3>
    <a href="{{auth_route_prefix}}/admin/list_users">Manage Users</a>
</div>
{% endif %}
```

### Including CSRF Token in Forms

```html
<form method="post" action="/api/update-profile">
    <input type="hidden" name="csrf_token" value="{{ user.csrf_token }}">
    <!-- form fields -->
    <button type="submit">Update</button>
</form>
```

## Template File Location

Place template files in a `templates/` directory at your crate root. Askama will look for templates relative to this directory based on the path specified in `#[template(path = "...")]`.

```
your-app/
├── Cargo.toml
├── src/
│   └── handlers.rs
└── templates/
    ├── index_anon.j2
    ├── index_user.j2
    └── protected.j2
```

## Dependencies

Add Askama to your `Cargo.toml`:

```toml
[dependencies]
askama = "0.12"
```
