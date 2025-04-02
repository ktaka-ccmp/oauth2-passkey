use serde::Serialize;
use std::env;
use std::sync::LazyLock;

use crate::passkey::config::{ORIGIN, PASSKEY_RP_ID};
use crate::passkey::errors::PasskeyError;

#[derive(Serialize)]
struct WebAuthnConfig {
    /// The WebAuthn relying party ID
    #[serde(rename = "rp_id")]
    rp_id: String,

    /// List of origins that are allowed to use this WebAuthn configuration
    #[serde(rename = "origins")]
    origins: Vec<String>,
}

// Static configuration for additional origins
static ADDITIONAL_ORIGINS: LazyLock<Vec<String>> = LazyLock::new(|| {
    env::var("WEBAUTHN_ADDITIONAL_ORIGINS")
        .map(|origins| {
            origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
});

/// Generate the WebAuthn configuration JSON
///
/// This function returns the WebAuthn configuration as a JSON string.
/// It includes the RP ID and all allowed origins (main origin + additional origins).
pub fn get_related_origin_json() -> Result<String, PasskeyError> {
    // Get the RP ID and origin
    let rp_id = PASSKEY_RP_ID.clone();
    let origin = ORIGIN.clone();

    // Collect all origins (main origin + additional origins)
    let mut origins = vec![origin];
    origins.extend(ADDITIONAL_ORIGINS.iter().cloned());

    // Create the WebAuthn configuration
    let config = WebAuthnConfig { rp_id, origins };

    // Serialize to JSON
    serde_json::to_string_pretty(&config).map_err(|e| PasskeyError::Serde(e.to_string()))
}
