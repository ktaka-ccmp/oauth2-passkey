use crate::passkey::PasskeyError;
use crate::storage::{CacheData, CacheKey, CachePrefix, get_data};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a passkey authenticator device.
///
/// This struct contains metadata about an authenticator based on its AAGUID
/// (Authenticator Attestation Globally Unique Identifier), which uniquely
/// identifies the make and model of the authenticator.
///
/// The information includes the device name and optional icon URLs for
/// light and dark themes.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthenticatorInfo {
    /// Name of the authenticator device or manufacturer
    pub name: String,
    /// URL to an icon suitable for dark mode/theme
    pub icon_dark: Option<String>,
    /// URL to an icon suitable for light mode/theme
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

impl From<AuthenticatorInfo> for CacheData {
    fn from(info: AuthenticatorInfo) -> Self {
        let value = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string()); // Fallback to empty JSON on serialization error
        CacheData { value }
    }
}

impl TryFrom<CacheData> for AuthenticatorInfo {
    type Error = PasskeyError;

    fn try_from(cache_data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&cache_data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
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
        let cache_prefix = CachePrefix::aaguid();
        let cache_key =
            CacheKey::new(aaguid.to_string()).map_err(|e| PasskeyError::Storage(e.to_string()))?;

        // Use simplified cache API for meaningful AAGUID keys (1 year = 31536000 seconds, effectively permanent)
        crate::storage::store_cache_keyed::<_, PasskeyError>(
            cache_prefix,
            cache_key,
            info.clone(),
            31536000,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to store AAGUID {} in cache: {}", aaguid, e);
            e
        })?;
    }
    tracing::info!(
        "Successfully loaded {} AAGUID mappings into cache",
        aaguid_map.0.len()
    );
    Ok(())
}

/// Retrieves information about an authenticator based on its AAGUID.
///
/// Given an AAGUID string (a UUID that identifies an authenticator make and model),
/// this function returns metadata about the authenticator including its name and
/// optional icon URLs.
///
/// # Arguments
///
/// * `aaguid` - The AAGUID string (e.g., "f8a011f3-8c0a-4d15-8006-17111f9edc7d")
///
/// # Returns
///
/// * `Ok(Some(AuthenticatorInfo))` - If information for the AAGUID exists in the cache
/// * `Ok(None)` - If no information is found for the given AAGUID
/// * `Err(PasskeyError)` - If an error occurs during the lookup
pub async fn get_authenticator_info(
    aaguid: &str,
) -> Result<Option<AuthenticatorInfo>, PasskeyError> {
    let cache_prefix = CachePrefix::aaguid();
    let cache_key =
        CacheKey::new(aaguid.to_string()).map_err(|e| PasskeyError::Storage(e.to_string()))?;

    get_data::<AuthenticatorInfo, PasskeyError>(cache_prefix, cache_key).await
}

/// Retrieves information for multiple authenticators in a batch.
///
/// This function efficiently fetches metadata for multiple authenticators at once
/// by their AAGUIDs, returning a map of AAGUID to authenticator information.
///
/// # Arguments
///
/// * `aaguids` - A slice of AAGUID strings to look up
///
/// # Returns
///
/// * `Ok(HashMap<String, AuthenticatorInfo>)` - A map containing all found authenticator
///   information, with AAGUIDs as keys. AAGUIDs that weren't found will not be included.
/// * `Err(PasskeyError)` - If an error occurs during lookup
pub async fn get_authenticator_info_batch(
    aaguids: &[String],
) -> Result<HashMap<String, AuthenticatorInfo>, PasskeyError> {
    let mut result = HashMap::new();

    // Process each AAGUID using unified cache operations
    for aaguid in aaguids {
        let cache_prefix = CachePrefix::aaguid();
        if let Ok(cache_key) = CacheKey::new(aaguid.clone())
            && let Ok(Some(info)) =
                get_data::<AuthenticatorInfo, PasskeyError>(cache_prefix, cache_key).await
        {
            result.insert(aaguid.clone(), info);
        }
        // Silently ignore errors for individual entries to maintain batch operation behavior
    }
    Ok(result)
}
#[cfg(test)]
mod tests;
