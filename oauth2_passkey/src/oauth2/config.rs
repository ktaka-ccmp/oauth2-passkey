use crate::config::O2P_ROUTE_PREFIX;
use std::{env, sync::LazyLock};

pub(crate) static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

pub static OAUTH2_AUTH_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_AUTH_URL")
        .ok()
        .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth".to_string())
});
pub(crate) static OAUTH2_TOKEN_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_TOKEN_URL")
        .ok()
        .unwrap_or("https://oauth2.googleapis.com/token".to_string())
});

static OAUTH2_SCOPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string()));

static OAUTH2_RESPONSE_MODE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string()));

static OAUTH2_RESPONSE_TYPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string()));

pub(crate) static OAUTH2_QUERY_STRING: LazyLock<String> = LazyLock::new(|| {
    let mut query_string = "".to_string();
    query_string.push_str(&format!("&response_type={}", *OAUTH2_RESPONSE_TYPE));
    query_string.push_str(&format!("&scope={}", *OAUTH2_SCOPE));
    query_string.push_str(&format!("&response_mode={}", *OAUTH2_RESPONSE_MODE));
    query_string.push_str(&format!("&access_type={}", "online"));
    query_string.push_str(&format!("&prompt={}", "consent"));
    query_string
});

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".

pub(crate) static OAUTH2_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub(crate) static OAUTH2_ENABLE_CSRF_FOR_POST_CALLBACKS: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("OAUTH2_ENABLE_CSRF_FOR_POST_CALLBACKS")
        .ok()
        .map(|s| s.to_lowercase() == "true")
        .unwrap_or(true) // Default to true for better security
});

pub(super) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 60 seconds if not set or invalid
});

pub(super) static OAUTH2_REDIRECT_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}{}/oauth2/authorized",
        env::var("ORIGIN").expect("Missing ORIGIN!"),
        O2P_ROUTE_PREFIX.as_str()
    )
});

pub(super) static OAUTH2_GOOGLE_CLIENT_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set")
});

pub(super) static OAUTH2_GOOGLE_CLIENT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set")
});
