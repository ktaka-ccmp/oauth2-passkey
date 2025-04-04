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
