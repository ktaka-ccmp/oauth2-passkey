//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

/// Route prefix for all oauth2_passkey endpoints
///
/// This is the main prefix under which all authentication endpoints will be mounted.
/// Default: "/o2p"
pub static O2P_ROUTE_PREFIX: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string()));

/// Sub-route for OAuth2 endpoints
///
/// This will be mounted under O2P_ROUTE_PREFIX
/// Full path: {O2P_ROUTE_PREFIX}/oauth2
pub const OAUTH2_SUB_ROUTE: &str = "/oauth2";

/// Sub-route for Passkey endpoints
///
/// This will be mounted under O2P_ROUTE_PREFIX
/// Full path: {O2P_ROUTE_PREFIX}/passkey
pub const PASSKEY_SUB_ROUTE: &str = "/passkey";

/// Sub-route for Summary endpoints
///
/// This will be mounted under O2P_ROUTE_PREFIX
/// Full path: {O2P_ROUTE_PREFIX}/summary
pub const SUMMARY_SUB_ROUTE: &str = "/summary";
