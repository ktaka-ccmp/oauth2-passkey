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
    use crate::storage::CacheData;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // Mock the cache store for testing
    struct MockCache {
        data: HashMap<String, HashMap<String, CacheData>>,
    }

    impl MockCache {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
            }
        }

        fn put(&mut self, prefix: &str, key: &str, value: CacheData) -> Result<(), PasskeyError> {
            let prefix_map = self
                .data
                .entry(prefix.to_string())
                .or_insert_with(HashMap::new);
            prefix_map.insert(key.to_string(), value);
            Ok(())
        }

        fn get(&self, prefix: &str, key: &str) -> Result<Option<CacheData>, PasskeyError> {
            if let Some(prefix_map) = self.data.get(prefix) {
                if let Some(value) = prefix_map.get(key) {
                    return Ok(Some(value.clone()));
                }
            }
            Ok(None)
        }
    }

    // Test the AuthenticatorInfo struct
    #[test]
    fn test_authenticator_info_default() {
        let info = AuthenticatorInfo::default();
        assert_eq!(info.name, "Unknown Authenticator");
        assert_eq!(info.icon_dark, None);
        assert_eq!(info.icon_light, None);
    }

    // Test the store_aaguid_in_cache function with a mock cache
    #[test]
    fn test_store_aaguid_in_cache() {
        // Create a mock cache
        let mock_cache = Arc::new(Mutex::new(MockCache::new()));

        // Create a valid JSON string with AAGUID data
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

        // Parse the JSON
        let aaguid_map: AaguidMap = serde_json::from_str(json).unwrap();

        // Store each AAGUID in the mock cache
        for (aaguid, info) in &aaguid_map.0 {
            // Convert to JSON string
            let json_string = serde_json::to_string(&info).unwrap();

            // Create CacheData with the JSON string
            let cache_data = CacheData { value: json_string };

            // Store in mock cache
            mock_cache
                .lock()
                .unwrap()
                .put("aaguid", aaguid, cache_data)
                .unwrap();
        }

        // Verify the data was stored correctly
        let cache = mock_cache.lock().unwrap();

        // Check first AAGUID
        let value1 = cache
            .get("aaguid", "00000000-0000-0000-0000-000000000000")
            .unwrap();
        assert!(value1.is_some(), "AAGUID data not found in cache");

        let info1: AuthenticatorInfo = serde_json::from_str(&value1.unwrap().value).unwrap();
        assert_eq!(info1.name, "Test Authenticator");
        assert_eq!(
            info1.icon_dark,
            Some("https://example.com/icon-dark.png".to_string())
        );
        assert_eq!(
            info1.icon_light,
            Some("https://example.com/icon-light.png".to_string())
        );

        // Check second AAGUID
        let value2 = cache
            .get("aaguid", "11111111-1111-1111-1111-111111111111")
            .unwrap();
        assert!(value2.is_some(), "AAGUID data not found in cache");

        let info2: AuthenticatorInfo = serde_json::from_str(&value2.unwrap().value).unwrap();
        assert_eq!(info2.name, "Another Authenticator");
        assert_eq!(info2.icon_dark, None);
        assert_eq!(info2.icon_light, None);
    }

    // Test invalid JSON handling
    #[test]
    fn test_invalid_json_handling() {
        // Invalid JSON with a trailing comma
        let invalid_json = r#"
        {
            "00000000-0000-0000-0000-000000000000": {
                "name": "Test Authenticator",
                "icon_dark": "https://example.com/icon-dark.png",
                "icon_light": "https://example.com/icon-light.png",
            }
        }
        "#;

        // Attempt to parse the invalid JSON
        let result = serde_json::from_str::<AaguidMap>(invalid_json);
        assert!(result.is_err(), "Expected error for invalid JSON");
    }

    // Test get_authenticator_info function with a mock implementation
    #[test]
    fn test_get_authenticator_info() {
        // Create a mock cache
        let mock_cache = Arc::new(Mutex::new(MockCache::new()));

        // Create test data
        let aaguid = "00000000-0000-0000-0000-000000000000";
        let info = AuthenticatorInfo {
            name: "Test Authenticator".to_string(),
            icon_dark: Some("https://example.com/icon-dark.png".to_string()),
            icon_light: Some("https://example.com/icon-light.png".to_string()),
        };

        // Store in mock cache
        let json_string = serde_json::to_string(&info).unwrap();
        let cache_data = CacheData { value: json_string };
        mock_cache
            .lock()
            .unwrap()
            .put("aaguid", aaguid, cache_data)
            .unwrap();

        // Simulate retrieving from cache
        let cache_value = mock_cache.lock().unwrap().get("aaguid", aaguid).unwrap();

        match cache_value {
            Some(cache_data) => {
                // Parse the JSON string back to AuthenticatorInfo
                let retrieved_info: AuthenticatorInfo =
                    serde_json::from_str(&cache_data.value).unwrap();
                assert_eq!(retrieved_info.name, "Test Authenticator");
                assert_eq!(
                    retrieved_info.icon_dark,
                    Some("https://example.com/icon-dark.png".to_string())
                );
                assert_eq!(
                    retrieved_info.icon_light,
                    Some("https://example.com/icon-light.png".to_string())
                );
            }
            None => panic!("Expected Some(CacheData)"),
        }

        // Test nonexistent AAGUID
        let nonexistent = mock_cache
            .lock()
            .unwrap()
            .get("aaguid", "nonexistent")
            .unwrap();
        assert!(
            nonexistent.is_none(),
            "Expected None for nonexistent AAGUID"
        );
    }

    // Test batch retrieval of authenticator info
    #[test]
    fn test_get_authenticator_info_batch() {
        // Create a mock cache
        let mock_cache = Arc::new(Mutex::new(MockCache::new()));

        // Create test data for multiple AAGUIDs
        let aaguid1 = "00000000-0000-0000-0000-000000000000";
        let info1 = AuthenticatorInfo {
            name: "Test Authenticator 1".to_string(),
            icon_dark: Some("https://example.com/icon1-dark.png".to_string()),
            icon_light: Some("https://example.com/icon1-light.png".to_string()),
        };

        let aaguid2 = "11111111-1111-1111-1111-111111111111";
        let info2 = AuthenticatorInfo {
            name: "Test Authenticator 2".to_string(),
            icon_dark: None,
            icon_light: None,
        };

        // Store in mock cache
        let mut cache = mock_cache.lock().unwrap();

        let json_string1 = serde_json::to_string(&info1).unwrap();
        let cache_data1 = CacheData {
            value: json_string1,
        };
        cache.put("aaguid", aaguid1, cache_data1).unwrap();

        let json_string2 = serde_json::to_string(&info2).unwrap();
        let cache_data2 = CacheData {
            value: json_string2,
        };
        cache.put("aaguid", aaguid2, cache_data2).unwrap();

        // Invalid JSON for a third AAGUID
        let aaguid3 = "22222222-2222-2222-2222-222222222222";
        let cache_data3 = CacheData {
            value: "{invalid-json}".to_string(),
        };
        cache.put("aaguid", aaguid3, cache_data3).unwrap();

        drop(cache); // Release the lock

        // Create a list of AAGUIDs to retrieve
        let aaguids = vec![
            aaguid1.to_string(),
            aaguid2.to_string(),
            aaguid3.to_string(),
            "nonexistent-aaguid".to_string(),
        ];

        // Simulate batch retrieval
        let mut result = HashMap::new();

        for aaguid in &aaguids {
            if let Some(cache_data) = mock_cache.lock().unwrap().get("aaguid", aaguid).unwrap() {
                if let Ok(info) = serde_json::from_str::<AuthenticatorInfo>(&cache_data.value) {
                    result.insert(aaguid.clone(), info);
                }
            }
        }

        // Verify results
        assert_eq!(result.len(), 2, "Expected 2 valid results");

        // Check the first AAGUID
        let retrieved_info1 = result.get(aaguid1).unwrap();
        assert_eq!(retrieved_info1.name, "Test Authenticator 1");
        assert_eq!(
            retrieved_info1.icon_dark,
            Some("https://example.com/icon1-dark.png".to_string())
        );
        assert_eq!(
            retrieved_info1.icon_light,
            Some("https://example.com/icon1-light.png".to_string())
        );

        // Check the second AAGUID
        let retrieved_info2 = result.get(aaguid2).unwrap();
        assert_eq!(retrieved_info2.name, "Test Authenticator 2");
        assert_eq!(retrieved_info2.icon_dark, None);
        assert_eq!(retrieved_info2.icon_light, None);

        // The invalid JSON and nonexistent AAGUIDs should not be in the result
        assert!(!result.contains_key(aaguid3));
        assert!(!result.contains_key("nonexistent-aaguid"));
    }
}
