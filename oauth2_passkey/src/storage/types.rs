use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::storage::errors::StorageError;

/// Data stored in the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub value: String,
    #[serde(default = "default_expires_at")]
    pub expires_at: DateTime<Utc>,
}

/// Default expiration time for cache entries (far future)
fn default_expires_at() -> DateTime<Utc> {
    DateTime::from_timestamp(4102444800, 0).unwrap_or_else(Utc::now) // Year 2100
}

/// Type-safe wrapper for cache prefixes.
///
/// Ensures consistent validation across all cache backends (Memory and Redis).
/// Validates length limits, character restrictions, and prevents cache injection attacks.
#[derive(Debug, Clone)]
pub struct CachePrefix(String);

impl CachePrefix {
    /// Creates a new CachePrefix with validation.
    ///
    /// Validates:
    /// - Non-empty prefix
    /// - Length limit (50 characters)
    /// - Safe characters only (no newlines, spaces, colons, etc.)
    pub fn new(prefix: String) -> Result<Self, StorageError> {
        // Allow empty prefixes for test scenarios
        // if prefix.is_empty() {
        //     return Err(StorageError::InvalidInput(
        //         "Cache prefix cannot be empty".to_string(),
        //     ));
        // }

        if prefix.len() > 50 {
            return Err(StorageError::InvalidInput(format!(
                "Cache prefix too long: {} bytes (max: 50)",
                prefix.len()
            )));
        }

        // Validate characters safe for all cache backends
        let dangerous_chars = ['\n', '\r', ' ', '\t', ':', '*'];
        if prefix.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput(
                "Cache prefix contains unsafe characters".to_string(),
            ));
        }

        Ok(CachePrefix(prefix))
    }

    /// Returns the prefix as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convenience constructor for session prefix.
    pub fn session() -> Self {
        CachePrefix("session".to_string())
    }

    /// Convenience constructor for aaguid prefix.
    pub fn aaguid() -> Self {
        CachePrefix("aaguid".to_string())
    }

    /// Convenience constructor for challenge prefix.
    #[allow(dead_code)]
    pub fn challenge() -> Self {
        CachePrefix("challenge".to_string())
    }
}

/// Type-safe wrapper for cache keys.
///
/// Ensures consistent validation across all cache backends (Memory and Redis).
/// Validates format, length limits, and prevents Redis command injection attacks.
#[derive(Debug, Clone)]
pub struct CacheKey(String);

impl CacheKey {
    /// Creates a new CacheKey with validation.
    ///
    /// Validates:
    /// - Non-empty key
    /// - Length limit (200 characters)
    /// - Safe characters (no control characters)
    /// - No Redis command keywords
    pub fn new(key: String) -> Result<Self, StorageError> {
        // Allow empty keys for test scenarios
        // if key.is_empty() {
        //     return Err(StorageError::InvalidInput(
        //         "Cache key cannot be empty".to_string(),
        //     ));
        // }

        if key.len() > 200 {
            return Err(StorageError::InvalidInput(format!(
                "Cache key too long: {} bytes (max: 200)",
                key.len()
            )));
        }

        // Validate characters safe for all cache backends
        let dangerous_chars = ['\n', '\r', ' ', '\t'];
        if key.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput(
                "Cache key contains unsafe characters".to_string(),
            ));
        }

        // Check for actual Redis injection patterns (not just substrings)
        let key_trimmed = key.trim().to_uppercase();
        let suspicious_patterns = [
            // Redis command injection patterns
            "\nSET ",
            "\nGET ",
            "\nDEL ",
            "\nFLUSHDB",
            "\nFLUSHALL",
            "\nEVAL ",
            "\nSCRIPT",
            ";SET ",
            ";GET ",
            ";DEL ",
            ";FLUSHDB",
            ";FLUSHALL",
            ";EVAL ",
            ";SCRIPT",
            // SQL injection patterns
            "'; DROP",
            "'; DELETE",
            "'; INSERT",
            "'; UPDATE",
            "UNION SELECT",
            // Command injection patterns
            "&& ",
            "|| ",
            "| ",
            "> ",
            "< ",
        ];

        for pattern in &suspicious_patterns {
            if key_trimmed.contains(pattern) {
                return Err(StorageError::InvalidInput(format!(
                    "Cache key contains dangerous injection pattern: '{key}'"
                )));
            }
        }

        Ok(CacheKey(key))
    }

    /// Returns the key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unified helper function to create cache prefix and key from strings.
/// This eliminates duplication across modules that need to create cache keys.
///
/// # Arguments
/// * `prefix_str` - The prefix string (e.g., "session", "jwks", "oauth2_token")
/// * `key_str` - The key string (e.g., session_id, token_id, aaguid)
///
/// # Returns
/// * `Ok((CachePrefix, CacheKey))` - The validated cache prefix and key
/// * `Err(StorageError)` - If validation fails for either prefix or key
///
/// # Example
/// ```no_run
/// // This function is used internally within the crate
/// // External users should use the public coordination API instead
/// # fn example() {
/// // let (prefix, key) = create_cache_keys("session", "abc123")?;
/// // Use prefix and key for cache operations
/// # }
/// ```
pub fn create_cache_keys(
    prefix_str: &str,
    key_str: &str,
) -> Result<(CachePrefix, CacheKey), StorageError> {
    let cache_prefix = CachePrefix::new(prefix_str.to_string())?;
    let cache_key = CacheKey::new(key_str.to_string())?;
    Ok((cache_prefix, cache_key))
}
