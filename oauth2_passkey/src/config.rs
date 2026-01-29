//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

/// Route prefix for all oauth2_passkey endpoints
///
/// This is the main prefix under which all authentication endpoints will be mounted.
/// Default: "/o2p"
pub static O2P_ROUTE_PREFIX: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string()));

/// Signal API mode for credential synchronization with authenticators.
///
/// Controls which WebAuthn Signal APIs are called for credential deletion and login sync:
/// - `"direct"`: Use `signalUnknownCredential` only (default, currently the only working API
///   with Google Password Manager)
/// - `"sync"`: Use `signalAllAcceptedCredentials` only (currently no effect on Chrome,
///   may work with other authenticators)
/// - `"direct+sync"`: Use both APIs for maximum compatibility
///
/// Default: "direct"
pub static PASSKEY_SIGNAL_API_MODE: LazyLock<String> = LazyLock::new(|| {
    let mode = std::env::var("PASSKEY_SIGNAL_API_MODE").unwrap_or_else(|_| "direct".to_string());
    let valid_modes = ["direct", "sync", "direct+sync"];
    if !valid_modes.contains(&mode.as_str()) {
        tracing::warn!(
            "Invalid PASSKEY_SIGNAL_API_MODE '{}', valid values are: {:?}. Using 'direct'.",
            mode,
            valid_modes
        );
        "direct".to_string()
    } else {
        mode
    }
});

#[cfg(test)]
mod tests;
