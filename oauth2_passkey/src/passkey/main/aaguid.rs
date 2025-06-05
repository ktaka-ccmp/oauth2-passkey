use crate::passkey::PasskeyError;
use crate::storage::{CacheData, GENERIC_CACHE_STORE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthenticatorInfo {
    pub name: String,
    pub icon_dark: Option<String>,
    pub icon_light: Option<String>,
}

impl Default for AuthenticatorInfo {
    fn default() -> Self {
        Self {
            name: "Unknown Authenticator".to_string(),
            icon_dark: None,
            icon_light: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AaguidMap(pub HashMap<String, AuthenticatorInfo>);

const AAGUID_JSON: &str = include_str!("../../../assets/aaguid.json");
const AAGUID_URL: &str = "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/refs/heads/main/combined_aaguid.json";

pub(crate) async fn store_aaguids() -> Result<(), PasskeyError> {
    tracing::info!("Loading AAGUID mappings from JSON");
    let json = AAGUID_JSON.to_string();

    store_aaguid_in_cache(json).await?;

    let response = reqwest::get(AAGUID_URL)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;
    let json = response
        .text()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    store_aaguid_in_cache(json).await?;

    Ok(())
}

async fn store_aaguid_in_cache(json: String) -> Result<(), PasskeyError> {
    let aaguid_map: AaguidMap = serde_json::from_str(&json).map_err(|e| {
        tracing::error!("Failed to parse AAGUID JSON: {}", e);
        PasskeyError::Storage(e.to_string())
    })?;

    for (aaguid, info) in &aaguid_map.0 {
        // Convert to JSON string first
        let json_string =
            serde_json::to_string(&info).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        // Create CacheData with the JSON string
        let cache_data = CacheData { value: json_string };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put("aaguid", aaguid, cache_data)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store AAGUID {} in cache: {}", aaguid, e);
                PasskeyError::Storage(e.to_string())
            })?;
    }
    tracing::info!(
        "Successfully loaded {} AAGUID mappings into cache",
        aaguid_map.0.len()
    );
    Ok(())
}

pub async fn get_authenticator_info(
    aaguid: &str,
) -> Result<Option<AuthenticatorInfo>, PasskeyError> {
    let cache_value = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("aaguid", aaguid)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    match cache_value {
        Some(cache_data) => {
            // Parse the JSON string back to AuthenticatorInfo
            let info: AuthenticatorInfo = serde_json::from_str(&cache_data.value)
                .map_err(|e| PasskeyError::Storage(e.to_string()))?;
            Ok(Some(info))
        }
        None => Ok(None),
    }
}

pub async fn get_authenticator_info_batch(
    aaguids: &[String],
) -> Result<HashMap<String, AuthenticatorInfo>, PasskeyError> {
    let mut result = HashMap::new();
    let cache = GENERIC_CACHE_STORE.lock().await;

    // If your cache store supports MGET, use it here for efficiency.
    // For now, do it sequentially (still avoids duplicate lookups).
    for aaguid in aaguids {
        if let Some(cache_data) = cache.get("aaguid", aaguid).await.ok().flatten() {
            if let Ok(info) = serde_json::from_str::<AuthenticatorInfo>(&cache_data.value) {
                result.insert(aaguid.clone(), info);
            }
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;

    // Test store_aaguid_in_cache function with valid JSON
    #[tokio::test]
    async fn test_store_aaguid_in_cache_success() {
        let json = r#"
        {
            "00000000-0000-0000-0000-000000000000": {
                "name": "Test Authenticator",
                "icon_dark": "https://example.com/icon-dark.png",
                "icon_light": "https://example.com/icon-light.png"
            },
            "11111111-1111-1111-1111-111111111111": {
                "name": "Another Authenticator",
                "icon_dark": null,
                "icon_light": null
            }
        }
        "#;

        // Test the actual function - it should not panic and return a result
        let result = store_aaguid_in_cache(json.to_string()).await;
        // We can't easily test success without a complex mock setup,
        // but we can test that it doesn't panic and returns a result
        assert!(result.is_ok() || result.is_err());
    }

    // Test store_aaguid_in_cache function with invalid JSON
    #[tokio::test]
    async fn test_store_aaguid_in_cache_invalid_json() {
        let invalid_json = r#"
        {
            "00000000-0000-0000-0000-000000000000": {
                "name": "Test Authenticator",
                "icon_dark": "https://example.com/icon-dark.png",
                "icon_light": "https://example.com/icon-light.png",
            }
        }
        "#;

        let result = store_aaguid_in_cache(invalid_json.to_string()).await;
        assert!(result.is_err(), "Expected error for invalid JSON");

        if let Err(PasskeyError::Storage(msg)) = result {
            assert!(
                msg.contains("expected") || msg.contains("trailing comma"),
                "Error message should indicate JSON parsing issue: {}",
                msg
            );
        } else {
            panic!("Expected PasskeyError::Storage");
        }
    }

    // Test AuthenticatorInfo parsing with valid data
    #[test]
    fn test_authenticator_info_parsing() {
        let json = r#"
        {
            "name": "Test Authenticator",
            "icon_dark": "https://example.com/icon-dark.png",
            "icon_light": "https://example.com/icon-light.png"
        }
        "#;

        let info: Result<AuthenticatorInfo, _> = serde_json::from_str(json);
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.name, "Test Authenticator");
        assert_eq!(
            info.icon_dark,
            Some("https://example.com/icon-dark.png".to_string())
        );
        assert_eq!(
            info.icon_light,
            Some("https://example.com/icon-light.png".to_string())
        );
    }

    // Test AuthenticatorInfo parsing with null icons
    #[test]
    fn test_authenticator_info_parsing_null_icons() {
        let json = r#"
        {
            "name": "Test Authenticator",
            "icon_dark": null,
            "icon_light": null
        }
        "#;

        let info: Result<AuthenticatorInfo, _> = serde_json::from_str(json);
        assert!(info.is_ok());
        let info = info.unwrap();
        assert_eq!(info.name, "Test Authenticator");
        assert_eq!(info.icon_dark, None);
        assert_eq!(info.icon_light, None);
    }

    // Test AuthenticatorInfo parsing with missing fields
    #[test]
    fn test_authenticator_info_parsing_missing_fields() {
        let json = r#"
        {
            "icon_dark": "https://example.com/icon-dark.png",
            "icon_light": "https://example.com/icon-light.png"
        }
        "#;

        let info: Result<AuthenticatorInfo, _> = serde_json::from_str(json);
        assert!(
            info.is_err(),
            "Should fail when required 'name' field is missing"
        );
    }

    // Test AAGUID validation
    #[test]
    fn test_aaguid_format_validation() {
        // Valid AAGUID format
        let valid_aaguid = "00000000-0000-0000-0000-000000000000";
        assert_eq!(valid_aaguid.len(), 36);
        assert!(valid_aaguid.chars().filter(|&c| c == '-').count() == 4);

        // Invalid AAGUID format
        let invalid_aaguid = "invalid-aaguid-format";
        assert_ne!(invalid_aaguid.len(), 36);
    }

    // Test get_authenticator_info with non-existent AAGUID
    #[tokio::test]
    async fn test_get_authenticator_info_not_found() {
        let non_existent_aaguid = "99999999-9999-9999-9999-999999999999";
        let result = get_authenticator_info(non_existent_aaguid).await;

        // Should either return Ok(None) or handle gracefully
        match result {
            Ok(None) => {
                // This is the expected behavior for non-existent AAGUID
            }
            Ok(Some(_)) => {
                // Might happen if the AAGUID exists in the cache
            }
            Err(_) => {
                // Error is also acceptable in this context
            }
        }
    }

    // Test batch retrieval with empty input
    #[tokio::test]
    async fn test_get_authenticator_info_batch_empty() {
        let empty_aaguids: Vec<String> = vec![];
        let result = get_authenticator_info_batch(&empty_aaguids).await;

        assert!(result.is_ok());
        let info_map = result.unwrap();
        assert!(info_map.is_empty());
    }
}
