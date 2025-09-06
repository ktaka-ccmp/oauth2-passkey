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

/// Generates a JSON configuration for cross-origin WebAuthn credential use.
///
/// This function returns a JSON string containing the WebAuthn Relying Party ID and
/// all allowed origins where passkeys can be used (the main origin plus any additional
/// origins specified in the WEBAUTHN_ADDITIONAL_ORIGINS environment variable).
///
/// This is particularly useful for enabling cross-origin authentication in multi-domain
/// applications or when supporting different subdomains under the same RP ID.
///
/// # Returns
///
/// * `Ok(String)` - A JSON string containing the WebAuthn configuration
/// * `Err(PasskeyError)` - If an error occurs during JSON serialization
///
/// # Example JSON Output
/// ```json
/// {
///   "rp_id": "example.com",
///   "origins": [
///     "https://app.example.com",
///     "https://login.example.com"
///   ]
/// }
/// ```
pub fn get_related_origin_json() -> Result<String, PasskeyError> {
    get_related_origin_json_with_core(
        PASSKEY_RP_ID.clone(),
        ORIGIN.clone(),
        ADDITIONAL_ORIGINS.clone(),
    )
}

fn get_related_origin_json_with_core(
    rp_id: String,
    origin: String,
    additional_origins: Vec<String>,
) -> Result<String, PasskeyError> {
    // Collect all origins (main origin + additional origins)
    let mut origins = vec![origin];
    origins.extend(additional_origins.iter().cloned());

    // Create the WebAuthn configuration
    let config = WebAuthnConfig { rp_id, origins };

    // Serialize to JSON
    serde_json::to_string_pretty(&config).map_err(|e| PasskeyError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests;
