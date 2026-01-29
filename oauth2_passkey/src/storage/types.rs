use serde::{Deserialize, Serialize};

use crate::storage::errors::StorageError;

/// Data stored in the cache
///
/// Simplified structure that relies on Redis TTL for expiration instead of
/// application-level expires_at validation. This eliminates redundancy and
/// improves performance by leveraging Redis's native expiration mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheData {
    pub value: String,
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

    /// Convenience constructor for PKCE prefix.
    pub fn pkce() -> Self {
        CachePrefix("pkce".to_string())
    }

    /// Convenience constructor for nonce prefix.
    pub fn nonce() -> Self {
        CachePrefix("nonce".to_string())
    }

    /// Convenience constructor for CSRF prefix.
    pub fn csrf() -> Self {
        CachePrefix("csrf".to_string())
    }

    /// Convenience constructor for misc_session prefix.
    pub fn misc_session() -> Self {
        CachePrefix("misc_session".to_string())
    }

    /// Convenience constructor for mode prefix.
    pub fn mode() -> Self {
        CachePrefix("mode".to_string())
    }

    /// Convenience constructor for JWKS prefix.
    pub fn jwks() -> Self {
        CachePrefix("jwks".to_string())
    }

    /// Convenience constructor for authentication challenge prefix.
    pub fn auth_challenge() -> Self {
        CachePrefix("authentication".to_string())
    }

    /// Convenience constructor for registration challenge prefix.
    pub fn reg_challenge() -> Self {
        CachePrefix("registration".to_string())
    }

    /// Convenience constructor for session info prefix.
    pub fn session_info() -> Self {
        CachePrefix("session_info".to_string())
    }

    /// Convenience constructor for user sessions mapping prefix.
    ///
    /// Used to store the user_id -> session_id[] reverse index
    /// for tracking all active sessions per user.
    pub fn user_sessions() -> Self {
        CachePrefix("user_sessions".to_string())
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

#[cfg(test)]
mod tests;
