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
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use http::header::{HeaderMap, SET_COOKIE};

    #[test]
    fn test_base64url_encode_decode() {
        // Test with simple string
        let original = b"hello world";
        let encoded = base64url_encode(original.to_vec()).expect("Failed to encode");
        let decoded = base64url_decode(&encoded).expect("Failed to decode");
        assert_eq!(decoded, original);

        // Test with empty input
        let empty_encoded = base64url_encode(vec![]).expect("Failed to encode empty");
        let empty_decoded = base64url_decode(&empty_encoded).expect("Failed to decode empty");
        assert!(empty_decoded.is_empty());
    }

    #[test]
    fn test_base64url_decode_invalid() {
        // Test with invalid base64url string
        let invalid_base64 = "This is not base64url!";
        let result = base64url_decode(invalid_base64);
        assert!(matches!(result, Err(UtilError::Format(_))));
    }

    #[test]
    fn test_gen_random_string() {
        // Test different lengths
        for &len in &[0, 1, 10, 32, 64] {
            let result = gen_random_string(len);
            assert!(
                result.is_ok(),
                "Failed to generate random string of length {}",
                len
            );
            let s = result.unwrap();
            assert_eq!(s.len(), if len == 0 { 0 } else { (len * 4).div_ceil(3) });
        }

        // Verify strings are different
        let s1 = gen_random_string(32).unwrap();
        let s2 = gen_random_string(32).unwrap();
        assert_ne!(s1, s2, "Random strings should be different");
    }

    #[test]
    fn test_header_set_cookie() {
        let mut headers = HeaderMap::new();
        let name = "test_cookie".to_string();
        let value = "test_value".to_string();
        let expires_at = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let max_age = 3600;

        let result = header_set_cookie(
            &mut headers,
            name.clone(),
            value.clone(),
            expires_at,
            max_age,
        );

        assert!(result.is_ok());

        let cookies: Vec<_> = headers
            .get_all(SET_COOKIE)
            .into_iter()
            .filter_map(|v| v.to_str().ok())
            .collect();

        assert_eq!(cookies.len(), 1);
        let cookie = cookies[0];
        assert!(cookie.starts_with(&format!("{name}={value}")));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains(&format!("Max-Age={max_age}")));
    }

    #[test]
    fn test_header_set_cookie_invalid() {
        let mut headers = HeaderMap::new();
        // This should succeed even with spaces in the cookie name
        // since we're not validating cookie names in this version
        let result = header_set_cookie(
            &mut headers,
            "invalid name".to_string(),
            "value".to_string(),
            Utc::now(),
            3600,
        );

        assert!(
            result.is_ok(),
            "Should accept any cookie name in this version"
        );
    }
}
