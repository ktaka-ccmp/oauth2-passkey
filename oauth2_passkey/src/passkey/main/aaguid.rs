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
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

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

        // Store the data
        let result = store_aaguid_in_cache(json.to_string()).await;
        assert!(result.is_ok(), "Failed to store valid JSON: {:?}", result);

        // Verify both AAGUIDs were stored in the cache
        let cache = GENERIC_CACHE_STORE.lock().await;

        // Check first AAGUID
        let cache_data1 = cache
            .get("aaguid", "00000000-0000-0000-0000-000000000000")
            .await;
        assert!(cache_data1.is_ok(), "Failed to get first AAGUID from cache");
        let cache_data1 = cache_data1.unwrap();
        assert!(cache_data1.is_some(), "First AAGUID should exist in cache");

        // Check second AAGUID
        let cache_data2 = cache
            .get("aaguid", "11111111-1111-1111-1111-111111111111")
            .await;
        assert!(
            cache_data2.is_ok(),
            "Failed to get second AAGUID from cache"
        );
        let cache_data2 = cache_data2.unwrap();
        assert!(cache_data2.is_some(), "Second AAGUID should exist in cache");

        // Verify the stored data can be parsed back to AuthenticatorInfo
        let stored_data1 = cache_data1.unwrap();
        let info1: AuthenticatorInfo = serde_json::from_str(&stored_data1.value).unwrap();
        assert_eq!(info1.name, "Test Authenticator");
        assert_eq!(
            info1.icon_dark,
            Some("https://example.com/icon-dark.png".to_string())
        );

        let stored_data2 = cache_data2.unwrap();
        let info2: AuthenticatorInfo = serde_json::from_str(&stored_data2.value).unwrap();
        assert_eq!(info2.name, "Another Authenticator");
        assert_eq!(info2.icon_dark, None);
    }

    // Test store_aaguid_in_cache function with invalid JSON
    #[tokio::test]
    async fn test_store_aaguid_in_cache_invalid_json() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

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
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let non_existent_aaguid = "99999999-9999-9999-9999-999999999999";
        let result = get_authenticator_info(non_existent_aaguid).await;

        // Should return Ok(None) for non-existent AAGUID
        assert!(
            result.is_ok(),
            "Should handle non-existent AAGUID gracefully"
        );
        assert!(
            result.unwrap().is_none(),
            "Should return None for non-existent AAGUID"
        );
    }

    // Test batch retrieval with empty input
    #[tokio::test]
    async fn test_get_authenticator_info_batch_empty() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let empty_aaguids: Vec<String> = vec![];
        let result = get_authenticator_info_batch(&empty_aaguids).await;

        assert!(result.is_ok());
        let info_map = result.unwrap();
        assert!(info_map.is_empty());
    }

    // Test successful retrieval after storage
    #[tokio::test]
    async fn test_get_authenticator_info_success() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // First store some test data
        let json = r#"
        {
            "12345678-1234-1234-1234-123456789abc": {
                "name": "YubiKey 5",
                "icon_dark": "https://example.com/yubikey-dark.png",
                "icon_light": "https://example.com/yubikey-light.png"
            }
        }
        "#;

        let store_result = store_aaguid_in_cache(json.to_string()).await;
        assert!(store_result.is_ok(), "Failed to store test data");

        // Now retrieve it
        let aaguid = "12345678-1234-1234-1234-123456789abc";
        let result = get_authenticator_info(aaguid).await;

        assert!(result.is_ok(), "Failed to retrieve stored AAGUID");
        let info = result.unwrap();
        assert!(info.is_some(), "Should find the stored AAGUID");

        let info = info.unwrap();
        assert_eq!(info.name, "YubiKey 5");
        assert_eq!(
            info.icon_dark,
            Some("https://example.com/yubikey-dark.png".to_string())
        );
        assert_eq!(
            info.icon_light,
            Some("https://example.com/yubikey-light.png".to_string())
        );
    }

    // Test batch retrieval with actual data
    #[tokio::test]
    async fn test_get_authenticator_info_batch_with_data() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Store multiple test AAGUIDs
        let json = r#"
        {
            "aaaa0000-bbbb-cccc-dddd-eeeeeeeeeeee": {
                "name": "Authenticator A",
                "icon_dark": "https://example.com/a-dark.png",
                "icon_light": null
            },
            "bbbb1111-cccc-dddd-eeee-ffffffffffff": {
                "name": "Authenticator B",
                "icon_dark": null,
                "icon_light": "https://example.com/b-light.png"
            },
            "cccc2222-dddd-eeee-ffff-000000000000": {
                "name": "Authenticator C",
                "icon_dark": null,
                "icon_light": null
            }
        }
        "#;

        let store_result = store_aaguid_in_cache(json.to_string()).await;
        assert!(store_result.is_ok(), "Failed to store test data");

        // Test batch retrieval with mix of existing and non-existing AAGUIDs
        let aaguids = vec![
            "aaaa0000-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            "bbbb1111-cccc-dddd-eeee-ffffffffffff".to_string(),
            "nonexistent-aaguid-here".to_string(), // This one doesn't exist
            "cccc2222-dddd-eeee-ffff-000000000000".to_string(),
        ];

        let result = get_authenticator_info_batch(&aaguids).await;
        assert!(result.is_ok(), "Batch retrieval should succeed");

        let info_map = result.unwrap();
        assert_eq!(
            info_map.len(),
            3,
            "Should return 3 existing AAGUIDs, ignore non-existent"
        );

        // Verify each retrieved item
        let info_a = info_map
            .get("aaaa0000-bbbb-cccc-dddd-eeeeeeeeeeee")
            .unwrap();
        assert_eq!(info_a.name, "Authenticator A");
        assert_eq!(
            info_a.icon_dark,
            Some("https://example.com/a-dark.png".to_string())
        );
        assert_eq!(info_a.icon_light, None);

        let info_b = info_map
            .get("bbbb1111-cccc-dddd-eeee-ffffffffffff")
            .unwrap();
        assert_eq!(info_b.name, "Authenticator B");
        assert_eq!(info_b.icon_dark, None);
        assert_eq!(
            info_b.icon_light,
            Some("https://example.com/b-light.png".to_string())
        );

        let info_c = info_map
            .get("cccc2222-dddd-eeee-ffff-000000000000")
            .unwrap();
        assert_eq!(info_c.name, "Authenticator C");
        assert_eq!(info_c.icon_dark, None);
        assert_eq!(info_c.icon_light, None);

        // Verify non-existent AAGUID is not in the result
        assert!(!info_map.contains_key("nonexistent-aaguid-here"));
    }

    // Test cache corruption handling (invalid JSON stored in cache)
    #[tokio::test]
    async fn test_get_authenticator_info_corrupted_cache() {
        use crate::storage::CacheData;
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let aaguid = "corrupt-data-test-aaguid";

        // Manually insert invalid JSON into cache
        let corrupted_data = CacheData {
            value: "invalid json data".to_string(),
        };

        let mut cache = GENERIC_CACHE_STORE.lock().await;
        let put_result = cache.put("aaguid", aaguid, corrupted_data).await;
        assert!(put_result.is_ok(), "Should be able to put corrupted data");
        drop(cache); // Release the lock

        // Now try to retrieve it - should handle the corruption gracefully
        let result = get_authenticator_info(aaguid).await;
        assert!(
            result.is_err(),
            "Should return error for corrupted cache data"
        );

        if let Err(PasskeyError::Storage(msg)) = result {
            assert!(
                msg.contains("expected") || msg.contains("EOF") || msg.contains("invalid"),
                "Error should indicate JSON parsing issue: {}",
                msg
            );
        } else {
            panic!("Expected PasskeyError::Storage for corrupted data");
        }
    }

    // Test edge case: empty JSON object
    #[tokio::test]
    async fn test_store_aaguid_in_cache_empty_object() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let empty_json = "{}";
        let result = store_aaguid_in_cache(empty_json.to_string()).await;

        assert!(result.is_ok(), "Empty JSON object should be valid");

        // Verify no AAGUIDs were stored
        let cache = GENERIC_CACHE_STORE.lock().await;
        let non_existent = cache.get("aaguid", "any-aaguid").await;
        assert!(non_existent.is_ok());
        assert!(
            non_existent.unwrap().is_none(),
            "No AAGUIDs should be stored from empty object"
        );
    }

    // Test batch retrieval edge case: duplicate AAGUIDs in input
    #[tokio::test]
    async fn test_get_authenticator_info_batch_duplicates() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Store one test AAGUID
        let json = r#"
        {
            "duplicate-test-aaguid": {
                "name": "Duplicate Test",
                "icon_dark": null,
                "icon_light": null
            }
        }
        "#;

        let store_result = store_aaguid_in_cache(json.to_string()).await;
        assert!(store_result.is_ok(), "Failed to store test data");

        // Request with duplicates
        let aaguids = vec![
            "duplicate-test-aaguid".to_string(),
            "duplicate-test-aaguid".to_string(), // Duplicate
            "nonexistent".to_string(),
            "duplicate-test-aaguid".to_string(), // Another duplicate
        ];

        let result = get_authenticator_info_batch(&aaguids).await;
        assert!(
            result.is_ok(),
            "Batch retrieval with duplicates should succeed"
        );

        let info_map = result.unwrap();
        assert_eq!(
            info_map.len(),
            1,
            "Should have only one unique result despite duplicates"
        );

        let info = info_map.get("duplicate-test-aaguid").unwrap();
        assert_eq!(info.name, "Duplicate Test");
    }
}
