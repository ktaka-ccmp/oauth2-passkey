# oauth2_passkey

## Table of Contents

- [Basic usage](#basic-usage)
- [Prepare database and cache server](#prepare-database-and-cache-server)
- [Prepare .env file](#prepare-env-file)
- [Rust code](#rust-code)
- [Feature flags](#feature-flags)
- [Route protection](#route-protection)
- [Security](#security)

## Basic usage

### Prepare database and cache

#### Database

##### sqlite:

Make sure db url you specified is writable.

##### Postgres:

```bash
docker compose -f db/postgresql/docker-compose.yaml up -d
```

#### Cache

##### Memory:

No preparation needed.

##### Redis:

```bash
docker compose -f db/redis/docker-compose.yaml up -d
```

### .env file

```toml
ORIGIN='https://your-domain.example.com'

OAUTH2_GOOGLE_CLIENT_ID='your-client-id.apps.googleusercontent.com'
OAUTH2_GOOGLE_CLIENT_SECRET='your-client-secret'

GENERIC_CACHE_STORE_TYPE=redis
GENERIC_CACHE_STORE_URL='redis://localhost:6379'

GENERIC_DATA_STORE_TYPE=sqlite
GENERIC_DATA_STORE_URL='sqlite:///tmp/sqlite.db'
```

Note:
- ORIGIN should not have trailing slash
- ORIGIN should be https, otherwise OAuth2 and Passkey will not work
- You can have a SSL proxy in front of your app, but the ORIGIN should be the one that is accessible from the outside and should have the https:// prefix.

- You can get OAuth2 client ID and secret from [Google API Console](https://console.cloud.google.com/auth/clients).
- You should place `$ORIGIN/o2p/oauth2/authorized` as a Authorized redirect URI in the Google. For example if the ORIGIN is `https://example.com` then place `https://example.com/o2p/oauth2/` there.


### Rust code

In your rust code do the followings:
- import the oauth2_passkey_axum crate
- call init().await?
- nest the oauth2_passkey_router to your router

```rust
use oauth2_passkey_axum::{
    AuthUser, O2P_LOGIN_URL, O2P_ROUTE_PREFIX, O2P_SUMMARY_URL, oauth2_passkey_router,
};
```

Just call the init() and nest the "oauth2_passkey_router()" under O2P_ROUTE_PREFIX(default=/o2p).

```rust
  dotenv().ok();
  oauth2_passkey_axum::init().await?;

  let app = Router::new()
      .route("/", get(index))
      .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
      .merge(protected::router());
```

## Feature flags

oauth2_passkey_axum prepares optional admin and user interfaces, which is enabled by default.

To controle the features we use two feature flags:
"admin-ui" and "user-ui" to enable admin and user interfaces respectively. 

The default feature is set in oauth2_passkey_axum/Cargo.toml as:

```toml
default = ["admin-ui", "user-ui"]
```

If you want to disable default features, set the following in your app's Cargo.toml:

```toml
oauth2_passkey_axum = { default-features = false, features = [] }
```

If you want to enable user-ui only, disable the default first, then specify "user-ui" in features option:

```toml
oauth2_passkey_axum = { default-features = false, features = ["user-ui"] }
```

## Who is admin

- The first user has admin previllage and never lose it.
- Any admin can give admin previllage to another user.

## Route Protection

#### Axum Extractor

checks if session_id is valid
extract struct AuthUser 
Redirect(GET) or 40x(PUT/POST/DELETE) if it fails

#### Middleware

We have prepared a setof functions for middleware.

is_authenticated

## Security

### CSRF protection

Every state changing endpoint must have csrf token verification.
You should include the csrf token in a header.

A csrf_token is automatically generated upon session creation and stored in session cache as a part of the session. 

Embedding the csrf_token in the page is the responsibility of the template engine. 

Use the csrf_token when making a state changing request.

The validity of the csrf_token is automatically verified either by axum extractor or middleware.

#### Axum Extractor

If you use axum extractor to protect a page....

If your handle has "user: AuthUser" as an argument the route is protected and axum extractor extract the user, which in our implementation includes csrf_token.

```rust
async fn handler_a(user: AuthUser) -> impl IntoResponse {
```

You should pass the csrf_token through your templating system to the page.
When you make a state changing request from the page, you should inclide the csrf_token as:

```javascript
fetch('/some_end_point', {
    method: 'POST',
    headers: {
        'X-CSRF-Token': 'your-csrf-token'
        ...
    },
    ...
});
```

Our extractor for the AuthUser automatically checks the validity of the X-CSRF-Token against the csrf token stored in session cache when extracting the AuthUser.

#### Middleware

is_authenticated_401, is_authenticated_redirect:
Verify the X-CSRF-Token against the one stored in the session cache.

is_authenticated_user_401, is_authenticated_user_redirect
The X-CSRF-Token is verified by AuthUser axum extractor
