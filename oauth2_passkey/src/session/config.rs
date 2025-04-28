use std::env;
use std::sync::LazyLock;

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

pub static USER_CONTEXT_TOKEN_COOKIE: LazyLock<String> = LazyLock::new(|| {
    std::env::var("USER_CONTEXT_TOKEN_COOKIE")
        .ok()
        .unwrap_or("__Host-ContextToken".to_string())
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

pub(super) static USE_CONTEXT_TOKEN_COOKIE: LazyLock<bool> = LazyLock::new(|| {
    match env::var("USE_CONTEXT_TOKEN_COOKIE") {
        Ok(val) => match val.as_str() {
            "true" => true,
            "false" => false,
            _ => panic!(
                "USE_CONTEXT_TOKEN_COOKIE must be 'true' or 'false', got '{}'.",
                val
            ),
        },
        Err(_) => true, // Default to true when not specified
    }
});

pub static O2P_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub static O2P_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("O2P_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

pub(super) static USE_O2P_CSRF_COOKIE: LazyLock<bool> = LazyLock::new(|| {
    match env::var("USE_O2P_CSRF_COOKIE") {
        Ok(val) => match val.as_str() {
            "true" => true,
            "false" => false,
            _ => panic!(
                "USE_O2P_CSRF_COOKIE must be 'true' or 'false', got '{}'.",
                val
            ),
        },
        Err(_) => true, // Default to true when not specified
    }
});
