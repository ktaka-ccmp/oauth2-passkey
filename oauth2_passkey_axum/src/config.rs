//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

use oauth2_passkey::O2P_ROUTE_PREFIX;

/// URL of the login page, used by middleware and AuthUser extractor to redirect unauthenticated users
///
/// When `login-ui` feature is enabled: defaults to the built-in login page (`/o2p/user/login`)
/// When `login-ui` feature is disabled: **must be set explicitly** via env var, otherwise the
/// program will panic at startup to prevent redirect loops
pub static O2P_LOGIN_URL: LazyLock<String> =
    LazyLock::new(|| match std::env::var("O2P_LOGIN_URL") {
        Ok(url) => url,
        Err(_) => {
            if cfg!(feature = "login-ui") {
                format!("{}/user/login", *O2P_ROUTE_PREFIX)
            } else {
                panic!(
                    "O2P_LOGIN_URL must be set when the login-ui feature is disabled. \
                     Set it to your custom login page URL (e.g., O2P_LOGIN_URL=/login)."
                );
            }
        }
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

/// Default redirect URL for authenticated-user flows
/// Used when: authenticated users visit login page, logout redirect target in templates
/// Default: "/"
pub static O2P_DEFAULT_REDIRECT: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_DEFAULT_REDIRECT").unwrap_or_else(|_| "/".to_string()));

/// Whether to add X-CSRF-Token header to responses
/// Default: true (can be disabled by setting O2P_RESPOND_WITH_X_CSRF_TOKEN=false)
pub static O2P_RESPOND_WITH_X_CSRF_TOKEN: LazyLock<bool> =
    LazyLock::new(|| match std::env::var("O2P_RESPOND_WITH_X_CSRF_TOKEN") {
        Err(_) => true,
        Ok(val) => match val.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!(
                "O2P_RESPOND_WITH_X_CSRF_TOKEN='{val}' is invalid. Valid values: true, false"
            ),
        },
    });

/// Optional URL for custom CSS to override default styles
/// Example: O2P_CUSTOM_CSS_URL=/static/my-theme.css
/// Users can override CSS Custom Properties in their custom CSS file
pub static O2P_CUSTOM_CSS_URL: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("O2P_CUSTOM_CSS_URL").ok());

/// Passkey promotion mode after OAuth2 login (experimental)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PasskeyPromotionMode {
    /// Disabled (default)
    Disabled,
    /// Show confirmation modal before registration
    Ask,
    /// Skip modal, go directly to WebAuthn registration dialog
    Force,
}

impl PasskeyPromotionMode {
    pub(crate) fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    pub(crate) fn is_force(self) -> bool {
        matches!(self, Self::Force)
    }
}

/// FedCM (Federated Credential Management) mode (experimental)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FedCMMode {
    /// Disabled (default)
    Disabled,
    /// Enabled
    Enabled,
}

impl FedCMMode {
    pub(crate) fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// FedCM support for OAuth2 login (experimental)
/// Values: true/enabled (enabled), anything else (disabled, default)
pub(crate) static O2P_FEDCM: LazyLock<FedCMMode> =
    LazyLock::new(|| match std::env::var("O2P_FEDCM") {
        Err(_) => FedCMMode::Disabled,
        Ok(val) => match val.to_lowercase().as_str() {
            "true" | "enabled" => FedCMMode::Enabled,
            "false" | "disabled" | "" => FedCMMode::Disabled,
            _ => {
                panic!("O2P_FEDCM='{val}' is invalid. Valid values: true, enabled, false, disabled")
            }
        },
    });

/// Passkey promotion after OAuth2 login (experimental)
/// Values: false (disabled, default), ask (show modal), force (skip modal)
pub(crate) static O2P_PASSKEY_PROMOTION: LazyLock<PasskeyPromotionMode> = LazyLock::new(|| {
    match std::env::var("O2P_PASSKEY_PROMOTION") {
        Err(_) => PasskeyPromotionMode::Disabled,
        Ok(val) => match val.to_lowercase().as_str() {
            "ask" => PasskeyPromotionMode::Ask,
            "force" => PasskeyPromotionMode::Force,
            "false" | "disabled" | "" => PasskeyPromotionMode::Disabled,
            _ => panic!(
                "O2P_PASSKEY_PROMOTION='{val}' is invalid. Valid values: ask, force, false, disabled"
            ),
        },
    }
});

#[cfg(test)]
mod tests;
