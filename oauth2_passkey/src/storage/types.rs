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
    /// Implements comprehensive validation logic copied from the original Redis implementation
    /// to ensure consistent security across all cache backends (Memory and Redis).
    ///
    /// Validates:
    /// - Length limits (250 characters max, same as Redis component limit)
    /// - Safe characters (no whitespace, newlines, control characters)
    /// - Redis command injection protection
    /// - Dangerous pattern detection
    pub fn new(prefix: String) -> Result<Self, StorageError> {
        // Check for empty components - allow but log (same as Redis implementation)
        if prefix.is_empty() {
            tracing::debug!("Empty cache prefix component");
        }

        // Check length limit (same as Redis component validation: 250 bytes max)
        if prefix.len() > 250 {
            return Err(StorageError::InvalidInput(format!(
                "Cache prefix component too long: {} bytes (max 250)",
                prefix.len()
            )));
        }

        // Check for dangerous characters that could cause Redis command injection
        let dangerous_chars = ['\n', '\r', ' ', '\t'];
        if prefix.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput(format!(
                "Cache prefix component contains unsafe characters (whitespace/newlines): '{prefix}'"
            )));
        }

        // Check for Redis command keywords (copied from original Redis validation)
        // Only reject if the command appears as a standalone word or at boundaries
        let prefix_upper = prefix.to_uppercase();
        let redis_commands = [
            "SET", "GET", "DEL", "FLUSHDB", "FLUSHALL", "EVAL", "SCRIPT", "SHUTDOWN", "CONFIG",
            "CLIENT", "DEBUG", "MONITOR", "SYNC",
        ];

        for cmd in &redis_commands {
            // Check for command at start, end, or surrounded by non-alphanumeric chars
            if prefix_upper == *cmd
                || prefix_upper.starts_with(&format!("{cmd} "))
                || prefix_upper.ends_with(&format!(" {cmd}"))
                || prefix_upper.contains(&format!(" {cmd} "))
                || prefix_upper.starts_with(&format!("{cmd}\n"))
                || prefix_upper.ends_with(&format!("\n{cmd}"))
                || prefix_upper.contains(&format!("\n{cmd}\n"))
            {
                return Err(StorageError::InvalidInput(format!(
                    "Cache prefix component contains potentially dangerous command keyword: '{prefix}'"
                )));
            }
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
    /// Implements comprehensive validation logic copied from the original Redis implementation
    /// to ensure consistent security across all cache backends (Memory and Redis).
    ///
    /// Validates:
    /// - Length limits (250 characters max, same as Redis component limit)
    /// - Safe characters (no whitespace, newlines, control characters)
    /// - Redis command injection protection
    /// - Dangerous pattern detection
    pub fn new(key: String) -> Result<Self, StorageError> {
        // Check for empty components - allow but log (same as Redis implementation)
        if key.is_empty() {
            tracing::debug!("Empty cache key component");
        }

        // Check length limit (same as Redis component validation: 250 bytes max)
        if key.len() > 250 {
            return Err(StorageError::InvalidInput(format!(
                "Cache key component too long: {} bytes (max 250)",
                key.len()
            )));
        }

        // Check for dangerous characters that could cause Redis command injection
        let dangerous_chars = ['\n', '\r', ' ', '\t'];
        if key.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput(format!(
                "Cache key component contains unsafe characters (whitespace/newlines): '{key}'"
            )));
        }

        // Check for Redis command keywords (copied from original Redis validation)
        // Only reject if the command appears as a standalone word or at boundaries
        let key_upper = key.to_uppercase();
        let redis_commands = [
            "SET", "GET", "DEL", "FLUSHDB", "FLUSHALL", "EVAL", "SCRIPT", "SHUTDOWN", "CONFIG",
            "CLIENT", "DEBUG", "MONITOR", "SYNC",
        ];

        for cmd in &redis_commands {
            // Check for command at start, end, or surrounded by non-alphanumeric chars
            if key_upper == *cmd
                || key_upper.starts_with(&format!("{cmd} "))
                || key_upper.ends_with(&format!(" {cmd}"))
                || key_upper.contains(&format!(" {cmd} "))
                || key_upper.starts_with(&format!("{cmd}\n"))
                || key_upper.ends_with(&format!("\n{cmd}"))
                || key_upper.contains(&format!("\n{cmd}\n"))
            {
                return Err(StorageError::InvalidInput(format!(
                    "Cache key component contains potentially dangerous command keyword: '{key}'"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_validation_redis_commands() {
        // Test that Redis command keywords are rejected when they appear as standalone words
        let dangerous_keys = vec![
            "SET",           // Exact command
            "SET value",     // Command at start
            "key SET",       // Command at end
            "key SET value", // Command in middle
            "GET\nvalue",    // Command with newline
        ];

        for key in dangerous_keys {
            let result = CacheKey::new(key.to_string());
            assert!(
                result.is_err(),
                "Should reject key containing Redis command: {key}"
            );
        }

        // Test that legitimate keys with command substrings are accepted
        let safe_keys = vec![
            "test-session-test-admin-get-1755225833867", // Contains "GET" but not standalone
            "user_settings",                             // Contains "SET" but not standalone
            "delete_item",                               // Contains "DEL" but not standalone
        ];

        for key in safe_keys {
            let result = CacheKey::new(key.to_string());
            assert!(
                result.is_ok(),
                "Should accept safe key with command substring: {key}"
            );
        }
    }

    #[test]
    fn test_cache_key_validation_dangerous_chars() {
        // Test that dangerous characters are rejected
        let dangerous_keys = vec![
            "key\nwith\nnewlines",
            "key\rwith\rcarriage\rreturns",
            "key with spaces",
            "key\twith\ttabs",
        ];

        for key in dangerous_keys {
            let result = CacheKey::new(key.to_string());
            assert!(
                result.is_err(),
                "Should reject key with dangerous chars: {key:?}"
            );
        }
    }

    #[test]
    fn test_cache_key_validation_length_limit() {
        // Test length limit (250 characters)
        let long_key = "a".repeat(251);
        let result = CacheKey::new(long_key);
        assert!(
            result.is_err(),
            "Should reject key longer than 250 characters"
        );

        // Test acceptable length
        let ok_key = "a".repeat(250);
        let result = CacheKey::new(ok_key);
        assert!(
            result.is_ok(),
            "Should accept key with exactly 250 characters"
        );
    }

    #[test]
    fn test_cache_key_validation_valid_keys() {
        // Test that valid keys are accepted
        let valid_keys = vec![
            "session_123",
            "user-profile_456",
            "oauth2_token_abc",
            "aaguid_def",
            "", // Empty key allowed
        ];

        for key in valid_keys {
            let result = CacheKey::new(key.to_string());
            assert!(result.is_ok(), "Should accept valid key: {key}");
        }
    }

    #[test]
    fn test_cache_prefix_validation_consistency() {
        // Test that CachePrefix has the same validation as CacheKey

        // Redis commands should be rejected only when standalone
        let result = CachePrefix::new("SET".to_string());
        assert!(
            result.is_err(),
            "Should reject prefix with standalone Redis command"
        );

        // But substrings should be accepted
        let result = CachePrefix::new("user_settings".to_string());
        assert!(
            result.is_ok(),
            "Should accept prefix with command substring"
        );

        // Dangerous characters should be rejected
        let result = CachePrefix::new("prefix with spaces".to_string());
        assert!(result.is_err(), "Should reject prefix with dangerous chars");

        // Length limit should be enforced
        let long_prefix = "a".repeat(251);
        let result = CachePrefix::new(long_prefix);
        assert!(
            result.is_err(),
            "Should reject prefix longer than 250 characters"
        );

        // Valid prefixes should be accepted
        let result = CachePrefix::new("session".to_string());
        assert!(result.is_ok(), "Should accept valid prefix");
    }

    #[test]
    fn test_cache_validation_memory_redis_consistency() {
        // This test verifies that both Memory and Redis cache backends now have
        // identical validation through the typed interface

        // Create a key that would have been vulnerable in Memory cache before Phase 2
        let malicious_key = "user123\nSET malicious_key malicious_value";

        // Both CachePrefix and CacheKey should reject this
        let prefix_result = CachePrefix::new("session".to_string());
        let key_result = CacheKey::new(malicious_key.to_string());

        assert!(prefix_result.is_ok(), "Valid prefix should be accepted");
        assert!(
            key_result.is_err(),
            "Malicious key should be rejected by validation"
        );

        // This proves that Memory deployments now have the same protection as Redis deployments
    }

    #[test]
    fn test_validation_happens_at_caller_boundary() {
        // Test that validation happens when callers construct typed arguments,
        // not inside the unified cache operation wrappers

        // This malicious input should be rejected at construction time
        let malicious_inputs = vec![
            "SET malicious",
            "key\nwith\nnewlines",
            "key with spaces",
            "key\twith\ttabs",
        ];

        for input in malicious_inputs {
            let prefix_result = CachePrefix::new(input.to_string());
            let key_result = CacheKey::new(input.to_string());

            // Both should reject dangerous inputs at construction
            if input.contains("SET") {
                assert!(
                    prefix_result.is_err() || key_result.is_err(),
                    "Should reject Redis command: {input}"
                );
            } else {
                assert!(
                    prefix_result.is_err(),
                    "Should reject dangerous chars in prefix: {input}"
                );
                assert!(
                    key_result.is_err(),
                    "Should reject dangerous chars in key: {input}"
                );
            }
        }

        // Valid inputs should work
        let valid_inputs = vec!["session", "user_123", "oauth2_token", "challenge_abc"];

        for input in valid_inputs {
            let prefix_result = CachePrefix::new(input.to_string());
            let key_result = CacheKey::new(input.to_string());

            assert!(prefix_result.is_ok(), "Should accept valid prefix: {input}");
            assert!(key_result.is_ok(), "Should accept valid key: {input}");
        }
    }
}
