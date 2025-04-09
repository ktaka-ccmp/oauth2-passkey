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
