use std::env;
use std::sync::LazyLock;

/// Name of the session cookie used for authentication.
///
/// By default, uses the secure "__Host-" prefix to enforce additional security constraints.
/// Can be configured via the SESSION_COOKIE_NAME environment variable.
///
/// The "__Host-" prefix ensures that cookies:
/// 1. Cannot be set from a non-secure context
/// 2. Must have the Path attribute set to "/"
/// 3. Cannot include a Domain attribute (preventing subdomain access)
pub static SESSION_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-SessionId".to_string())
});
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

// We're using a simple string representation for tokens instead of a struct
// to minimize dependencies and complexity

pub(super) static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> =
    LazyLock::new(|| match env::var("AUTH_SERVER_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => "default_secret_key_change_in_production"
            .to_string()
            .into_bytes(),
    });
