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
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // Test the WebAuthnConfig struct serialization
    #[test]
    fn test_webauthn_config_serialization() {
        let config = WebAuthnConfig {
            rp_id: "example.com".to_string(),
            origins: vec!["https://example.com".to_string()],
        };

        let json = serde_json::to_string_pretty(&config).unwrap();

        // Parse the JSON and verify the structure
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["rp_id"], "example.com");
        assert!(parsed["origins"].is_array());
        assert_eq!(parsed["origins"][0], "https://example.com");
    }

    // Test parsing of additional origins
    #[test]
    fn test_parse_additional_origins() {
        // Test with empty string
        let empty = "";
        let empty_result: Vec<String> = empty
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(empty_result.is_empty());

        // Test with whitespace and empty entries
        let with_spaces = "https://app1.example.com, , https://app2.example.com,  ,";
        let spaces_result: Vec<String> = with_spaces
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        assert_eq!(spaces_result.len(), 2);
        assert_eq!(spaces_result[0], "https://app1.example.com");
        assert_eq!(spaces_result[1], "https://app2.example.com");
    }

    // Test the JSON structure directly without relying on environment variables
    #[test]
    fn test_json_structure() {
        // Create a WebAuthnConfig directly
        let config = WebAuthnConfig {
            rp_id: "test.example.com".to_string(),
            origins: vec![
                "https://test.example.com".to_string(),
                "https://app1.example.com".to_string(),
                "https://app2.example.com".to_string(),
            ],
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&config).unwrap();

        // Parse and verify the structure
        let parsed: Value = serde_json::from_str(&json).unwrap();

        // Verify the structure
        assert_eq!(parsed["rp_id"], "test.example.com");
        assert!(parsed["origins"].is_array());
        assert_eq!(parsed["origins"].as_array().unwrap().len(), 3);
        assert_eq!(parsed["origins"][0], "https://test.example.com");
        assert_eq!(parsed["origins"][1], "https://app1.example.com");
        assert_eq!(parsed["origins"][2], "https://app2.example.com");
    }
}
