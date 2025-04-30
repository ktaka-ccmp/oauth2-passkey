# oauth2_passkey



## Feature flags

oauth2_passkey_axum crate has two feature flags:
"admin-ui" and "user-ui" to enable admin and user interfaces respectively. Default is to enabled for both of them.

To disable default features:

```toml
oauth2_passkey_axum = { path = "../oauth2_passkey_axum", default-features = false, features = [] }
```

To disable admin-ui feature:

```toml
oauth2_passkey_axum = { path = "../oauth2_passkey_axum", default-features = false, features = ["user-ui"] }
```
