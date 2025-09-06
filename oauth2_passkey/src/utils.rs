//! Utility functions for common operations across the library.
//!
//! This module provides various helper functions and utilities used throughout the
//! library, including crypto operations, encoding/decoding, header manipulation,
//! and other common tasks. These utilities help reduce code duplication and
//! provide consistent implementations for frequently needed operations.
//!
//! ## Key features:
//!
//! - Secure random generation
//! - Base64URL encoding/decoding
//! - HTTP header manipulation
//! - Cookie handling
//! - Common error types for utility operations

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use http::header::{HeaderMap, SET_COOKIE};
use ring::rand::SecureRandom;
use thiserror::Error;

// use crate::session::SessionError;
// use crate::passkey::PasskeyError;

// pub(crate) fn gen_random_string(len: usize) -> Result<String, SessionError> {
//     let rng = ring::rand::SystemRandom::new();
//     let mut session_id = vec![0u8; len];
//     rng.fill(&mut session_id)
//         .map_err(|_| SessionError::Crypto("Failed to generate random string".to_string()))?;
//     Ok(URL_SAFE_NO_PAD.encode(session_id))
// }

pub(crate) fn base64url_decode(input: &str) -> Result<Vec<u8>, UtilError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| UtilError::Format("Failed to decode base64url".to_string()))?;
    Ok(decoded)
}

pub(crate) fn base64url_encode(input: Vec<u8>) -> Result<String, UtilError> {
    Ok(URL_SAFE_NO_PAD.encode(input))
}

pub(crate) fn gen_random_string(len: usize) -> Result<String, UtilError> {
    let rng = ring::rand::SystemRandom::new();
    let mut session_id = vec![0u8; len];
    rng.fill(&mut session_id)
        .map_err(|_| UtilError::Crypto("Failed to generate random string".to_string()))?;
    let encoded = base64url_encode(session_id)
        .map_err(|_| UtilError::Crypto("Failed to encode random string".to_string()))?;
    Ok(encoded)
}

/// Generate a cryptographically secure random string with entropy validation.
///
/// This function provides enhanced security by:
/// 1. Using entropy-validated random generation with SystemRandom
/// 2. Validating entropy quality to catch degenerate cases
/// 3. Retry mechanism for entropy validation failures
///
/// # Arguments
/// * `len` - The length in bytes for the random data (before base64url encoding)
///
/// # Returns
/// * `Ok(String)` - A base64url encoded random string
/// * `Err(UtilError)` - If random generation fails or entropy is insufficient
pub(crate) fn gen_random_string_with_entropy_validation(len: usize) -> Result<String, UtilError> {
    const MAX_GENERATION_ATTEMPTS: usize = 10;

    for attempt in 1..=MAX_GENERATION_ATTEMPTS {
        let rng = ring::rand::SystemRandom::new();
        let mut random_bytes = vec![0u8; len];

        rng.fill(&mut random_bytes)
            .map_err(|_| UtilError::Crypto("Failed to generate random bytes".to_string()))?;

        // Basic entropy validation: ensure we don't have all zeros or all same bytes
        if validate_entropy(&random_bytes) {
            let encoded = base64url_encode(random_bytes)
                .map_err(|_| UtilError::Crypto("Failed to encode random string".to_string()))?;
            return Ok(encoded);
        }

        tracing::warn!(
            "Low entropy detected in random generation, attempt {}/{}",
            attempt,
            MAX_GENERATION_ATTEMPTS
        );
    }

    Err(UtilError::Crypto(
        "Failed to generate sufficiently random string after max attempts".to_string(),
    ))
}

/// Validate that random bytes have sufficient entropy.
///
/// This performs basic entropy checks to catch obviously degenerate cases
/// like all zeros or all same bytes, but allows normal cryptographic randomness.
fn validate_entropy(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    // Check for all zeros
    if bytes.iter().all(|&b| b == 0) {
        return false;
    }

    // Check for all same bytes
    let first_byte = bytes[0];
    if bytes.iter().all(|&b| b == first_byte) {
        return false;
    }

    // For cryptographically secure random data, basic checks are sufficient
    // More sophisticated entropy tests could reject valid random data
    true
}

/// Set a cookie in the provided headers with the given parameters.
///
/// # Arguments
/// * `headers` - The headers to add the cookie to
/// * `name` - The name of the cookie
/// * `value` - The value of the cookie
/// * `_expires_at` - The expiration time of the cookie (currently unused)
/// * `max_age` - The max age of the cookie in seconds
///
/// # Returns
/// * `Ok(&HeaderMap)` on success
/// * `Err(UtilError::Cookie)` if parsing the cookie fails
pub(crate) fn header_set_cookie(
    headers: &mut HeaderMap,
    name: String,
    value: String,
    _expires_at: DateTime<Utc>,
    max_age: i64,
) -> Result<&HeaderMap, UtilError> {
    let cookie =
        format!("{name}={value}; SameSite=Lax; Secure; HttpOnly; Path=/; Max-Age={max_age}");
    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| UtilError::Cookie("Failed to parse cookie".to_string()))?,
    );
    Ok(headers)
}

#[derive(Debug, Error, Clone)]
pub enum UtilError {
    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Invalid format: {0}")]
    Format(String),
}

#[cfg(test)]
mod tests;
