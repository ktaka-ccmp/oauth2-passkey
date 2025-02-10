use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use crate::storage::memory::InMemoryTokenStore;
use crate::storage::CacheStoreToken;

// static OAUTH2_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
// static OAUTH2_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub(crate) static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

pub(crate) static OAUTH2_AUTH_URL: LazyLock<String> = LazyLock::new(|| {
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

pub(crate) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 60 seconds if not set or invalid
});

pub static OAUTH2_ROUTE_PREFIX: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_ROUTE_PREFIX")
        .ok()
        .unwrap_or("/oauth2".to_string())
});

pub(crate) static OAUTH2_REDIRECT_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}{}/authorized",
        env::var("ORIGIN").expect("Missing ORIGIN!"),
        OAUTH2_ROUTE_PREFIX.as_str()
    )
});

pub(crate) static OAUTH2_GOOGLE_CLIENT_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set")
});

pub(crate) static OAUTH2_GOOGLE_CLIENT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set")
});

pub(crate) static TOKEN_STORE: LazyLock<Mutex<Box<dyn CacheStoreToken>>> =
    LazyLock::new(|| Mutex::new(Box::new(InMemoryTokenStore::new())));
