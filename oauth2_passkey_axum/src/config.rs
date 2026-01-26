//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

use oauth2_passkey::O2P_ROUTE_PREFIX;

/// URL of supplementary login page
/// Default: "/o2p/user/login"
pub static O2P_LOGIN_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_LOGIN_URL").unwrap_or_else(|_| format!("{}/user/login", *O2P_ROUTE_PREFIX))
});

/// URL of the user account management page
/// Default: "/o2p/user/account"
pub static O2P_ACCOUNT_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_ACCOUNT_URL")
        .unwrap_or_else(|_| format!("{}/user/account", *O2P_ROUTE_PREFIX))
});

/// URL of the admin index page
/// Default: "/o2p/admin/index"
pub static O2P_ADMIN_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_ADMIN_URL").unwrap_or_else(|_| format!("{}/admin/index", *O2P_ROUTE_PREFIX))
});

/// Default redirect URL for authentication flows
/// Used when: unauthenticated users access protected routes, authenticated users visit login page, after logout
/// Default: "/"
pub static O2P_DEFAULT_REDIRECT: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_DEFAULT_REDIRECT").unwrap_or_else(|_| "/".to_string()));

/// Whether to add X-CSRF-Token header to responses
/// Default: true (can be disabled by setting O2P_RESPOND_WITH_X_CSRF_TOKEN=false)
pub static O2P_RESPOND_WITH_X_CSRF_TOKEN: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("O2P_RESPOND_WITH_X_CSRF_TOKEN")
        .map(|val| val.to_lowercase() != "false")
        .unwrap_or(true)
});

/// Optional URL for custom CSS to override default styles
/// Example: O2P_CUSTOM_CSS_URL=/static/my-theme.css
/// Users can override CSS Custom Properties in their custom CSS file
pub static O2P_CUSTOM_CSS_URL: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("O2P_CUSTOM_CSS_URL").ok());
