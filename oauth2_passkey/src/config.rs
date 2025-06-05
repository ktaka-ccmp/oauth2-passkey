//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

/// Route prefix for all oauth2_passkey endpoints
///
/// This is the main prefix under which all authentication endpoints will be mounted.
/// Default: "/o2p"
pub static O2P_ROUTE_PREFIX: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string()));
