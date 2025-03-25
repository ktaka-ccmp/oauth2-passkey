//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

/// Route prefix for all oauth2_passkey endpoints
///
/// This is the main prefix under which all authentication endpoints will be mounted.
/// Default: "/o2p"
pub static O2P_REDIRECT_ANON: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_REDIRECT_ANON").unwrap_or_else(|_| "/o2p/user/login".to_string())
});

pub static O2P_REDIRECT_USER: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_REDIRECT_USER").unwrap_or_else(|_| "/o2p/user/summary".to_string())
});
