# Multi-Origin Passkey Setup

This page explains how to configure passkeys to work across multiple origins (subdomains) sharing the same Relying Party (RP) ID.

## When You Need This

**Single domain**: If your application runs on a single domain (e.g., `https://example.com`), you do NOT need this configuration.

**Multiple origins**: You need this when:
- Your app runs on multiple subdomains (e.g., `app.example.com` and `login.example.com`)
- You want passkeys registered on one subdomain to work on another
- You're sharing authentication across development and staging environments

## How It Works

WebAuthn passkeys are bound to a Relying Party ID (RP ID), not to a specific origin. By default, the RP ID matches your domain.

```
RP ID: example.com

Allowed Origins:
├── https://example.com         (main site)
├── https://app.example.com     (application)
└── https://login.example.com   (login portal)
```

All these origins share the same RP ID (`example.com`), so a passkey registered on any of them works on all of them.

The `/.well-known/webauthn` endpoint tells browsers which origins are allowed to use this RP ID.

## Configuration

### Step 1: Set Environment Variables

```bash
# .env

# Your main origin
ORIGIN=https://example.com

# The RP ID (usually your root domain)
PASSKEY_RP_ID=example.com

# Additional origins that can use the same passkeys
WEBAUTHN_ADDITIONAL_ORIGINS=https://app.example.com,https://login.example.com
```

### Step 2: Use the Unified Router

If you use `oauth2_passkey_full_router()` (recommended), the `/.well-known/webauthn` endpoint is automatically included when `WEBAUTHN_ADDITIONAL_ORIGINS` is set:

```rust,ignore
use axum::Router;
use oauth2_passkey_axum::{oauth2_passkey_full_router, init};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init().await?;

    let app = Router::new()
        // All auth routes + /.well-known/webauthn (when multi-origin is configured)
        .merge(oauth2_passkey_full_router());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

**Alternative**: If you use `oauth2_passkey_router()` directly, add the well-known router manually:

```rust,ignore
use axum::Router;
use oauth2_passkey_axum::{
    oauth2_passkey_router, passkey_well_known_router,
    init, O2P_ROUTE_PREFIX
};

let app = Router::new()
    .merge(passkey_well_known_router())
    .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router());
```

### Step 3: Verify Setup

After starting your server, verify the endpoint returns the correct configuration:

```bash
curl https://example.com/.well-known/webauthn
```

Expected response:

```json
{
  "rp_id": "example.com",
  "origins": [
    "https://example.com",
    "https://app.example.com",
    "https://login.example.com"
  ]
}
```

## Important Notes

### RP ID Requirements

The RP ID must be a parent domain of all origins:

| RP ID | Origin | Valid? |
|-------|--------|--------|
| `example.com` | `https://example.com` | Yes |
| `example.com` | `https://app.example.com` | Yes |
| `example.com` | `https://other-site.com` | No |

### Browser Support

Related Origins is supported in modern browsers. Check [caniuse.com](https://caniuse.com) for current browser support.

### Security Considerations

- The `/.well-known/webauthn` endpoint exposes only public configuration (RP ID and allowed origins)
- No authentication is required for this endpoint (browsers fetch it before authentication)
- Only list origins you actually control

## Troubleshooting

### Passkey not working on subdomain

1. Verify `WEBAUTHN_ADDITIONAL_ORIGINS` includes the subdomain
2. Check that `/.well-known/webauthn` is accessible from the subdomain
3. Ensure the RP ID is a parent domain of all origins

### 404 on /.well-known/webauthn

1. If using `oauth2_passkey_full_router()`: Verify `WEBAUTHN_ADDITIONAL_ORIGINS` is set
2. If using `oauth2_passkey_router()` directly: Add `.merge(passkey_well_known_router())` to your router

### Origins list is empty

Check that `ORIGIN` environment variable is set correctly.
