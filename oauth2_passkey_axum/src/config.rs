//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

use oauth2_passkey::O2P_ROUTE_PREFIX;

/// URL of supplementary login page
/// Default: "/o2p/user/login"
pub static O2P_LOGIN_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_LOGIN_URL").unwrap_or_else(|_| format!("{}/user/login", *O2P_ROUTE_PREFIX))
});

/// URL of supplementary summary page
/// Default: "/o2p/user/summary"
pub static O2P_SUMMARY_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_SUMMARY_URL")
        .unwrap_or_else(|_| format!("{}/user/summary", *O2P_ROUTE_PREFIX))
});

pub static O2P_REDIRECT_ANON: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_REDIRECT_ANON").unwrap_or_else(|_| "/".to_string()));
