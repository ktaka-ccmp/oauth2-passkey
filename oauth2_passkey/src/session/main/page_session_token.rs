//! Page session token functionality for session/page synchronization
//!
//! This module provides stateless token generation and verification for
//! ensuring that the user interacting with a page is the same as the
//! user in the session, preventing session/page desynchronization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::Sha256;

use crate::{
    session::{config::AUTH_SERVER_SECRET, errors::SessionError, types::StoredSession},
    storage::GENERIC_CACHE_STORE,
};

use super::session::get_session_id_from_headers;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_page_session_token(token: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

/// Verify that received page_session_token (obfuscated csrf_token) as a part of query param is same as the one
/// in the current user's session cache.
pub async fn verify_page_session_token(
    headers: &HeaderMap,
    page_session_token: Option<&String>,
) -> Result<(), SessionError> {
    let session_id: &str = match get_session_id_from_headers(headers) {
        Ok(Some(session_id)) => session_id,
        _ => {
            return Err(SessionError::PageSessionToken(
                "Session ID missing".to_string(),
            ));
        }
    };

    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    match page_session_token {
        Some(context) => {
            if context.as_str() != generate_page_session_token(&stored_session.csrf_token) {
                tracing::error!("Page session token does not match session user");
                return Err(SessionError::PageSessionToken(
                    "Page session token does not match session user".to_string(),
                ));
            }
        }
        None => {
            tracing::error!("Page session token missing");
            return Err(SessionError::PageSessionToken(
                "Page session token missing".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test generating a page session token
    /// This test verifies that page session token generation works correctly and consistently.
    /// It performs the following steps:
    /// 1. Generates page session token from a given CSRF token
    /// 2. Verifies that the token is non-empty and deterministic (same input produces same output)
    /// 3. Confirms that different CSRF tokens produce different page session tokens
    #[test]
    fn test_generate_page_session_token() {
        // Given a CSRF token
        let csrf_token = "test_csrf_token";

        // When generating a page session token
        let page_token = generate_page_session_token(csrf_token);

        // Then the token should be a non-empty string
        assert!(!page_token.is_empty());

        // And generating the token again with the same input should produce the same output
        let page_token2 = generate_page_session_token(csrf_token);
        assert_eq!(page_token, page_token2);

        // And different inputs should produce different outputs
        let different_token = generate_page_session_token("different_token");
        assert_ne!(page_token, different_token);
    }

    /// Test HMAC properties
    /// This test verifies that page session token generation exhibits proper HMAC properties.
    /// It performs the following steps:
    /// 1. Generates page session tokens from similar but different CSRF tokens
    /// 2. Verifies that different inputs produce different outputs (avalanche effect)
    /// 3. Confirms that generated tokens are URL-safe (no +, /, or = characters)
    #[test]
    fn test_generate_page_session_token_hmac_properties() {
        // Given two similar CSRF tokens
        let token1 = "token1";
        let token2 = "token2";

        // When generating page session tokens
        let page_token1 = generate_page_session_token(token1);
        let page_token2 = generate_page_session_token(token2);

        // Then the tokens should be different (avalanche effect)
        assert_ne!(page_token1, page_token2);

        // And the tokens should be URL-safe (no +, /, or = characters)
        assert!(!page_token1.contains('+'));
        assert!(!page_token1.contains('/'));
        assert!(!page_token1.contains('='));
        assert!(!page_token2.contains('+'));
        assert!(!page_token2.contains('/'));
        assert!(!page_token2.contains('='));
    }

    /// Test generating a page session token with an empty string
    /// This test verifies that page session token generation handles edge cases like empty inputs.
    /// It performs the following steps:
    /// 1. Generates page session token from empty CSRF token string
    /// 2. Verifies that even with empty input, a non-empty token is generated
    /// 3. Confirms that the function handles edge cases gracefully
    #[test]
    fn test_generate_page_session_token_with_empty_string() {
        // Given an empty CSRF token
        let empty_token = "";

        // When generating a page session token
        let page_token = generate_page_session_token(empty_token);

        // Then the token should still be a non-empty string
        assert!(!page_token.is_empty());
    }

    // Helper function to create a test StoredSession for unit tests
    fn create_test_session(csrf_token: &str) -> serde_json::Value {
        use chrono::Utc;

        // Create a JSON representation matching StoredSession structure
        serde_json::json!({
            "user_id": "test_user",
            "csrf_token": csrf_token,
            "expires_at": Utc::now().to_rfc3339(),
            "ttl": 3600_u64,
        })
    }

    // Helper function to get the session cookie name for tests
    fn get_session_cookie_name() -> &'static str {
        "__Host-SessionId" // Match the default in SESSION_COOKIE_NAME
    }

    /// Test verifying a page session token
    /// This test verifies that page session token verification works correctly with valid session data.
    /// It performs the following steps:
    /// 1. Stores valid session with CSRF token in cache
    /// 2. Creates proper HTTP headers with session cookie and generates page token
    /// 3. Calls verify_page_session_token and confirms successful verification
    #[tokio::test]
    async fn test_verify_page_session_token_success() {
        use crate::storage::CacheData;
        use crate::test_utils::init_test_environment;
        use http::HeaderMap;
        use http::header::{COOKIE, HeaderValue};

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_123";
        let csrf_token = "test_csrf_token_456";

        // Create test session data as JSON
        let session_json = create_test_session(csrf_token);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
        };

        // Store the session in the global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl("session", session_id, cache_data, 3600)
            .await
            .unwrap();

        // Create headers with session cookie
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", get_session_cookie_name(), session_id))
                .unwrap(),
        );

        // Generate the expected page session token
        let page_token = generate_page_session_token(csrf_token);

        // Test verification success using global store
        let result = verify_page_session_token(&headers, Some(&page_token)).await;

        assert!(result.is_ok());
    }

    /// Test verifying a page session token with an invalid token
    /// This test verifies that page session token verification correctly rejects invalid tokens.
    /// It performs the following steps:
    /// 1. Stores valid session with CSRF token in cache
    /// 2. Creates HTTP headers with session cookie but provides wrong page session token
    /// 3. Confirms that verification fails with "does not match" error for invalid tokens
    #[tokio::test]
    async fn test_verify_page_session_token_invalid_token() {
        use crate::storage::CacheData;
        use crate::test_utils::init_test_environment;
        use http::HeaderMap;
        use http::header::{COOKIE, HeaderValue};

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_789";
        let csrf_token = "actual_csrf_token";

        // Create test session data as JSON
        let session_json = create_test_session(csrf_token);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
        };

        // Store the session in the global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl("session", session_id, cache_data, 3600)
            .await
            .unwrap();

        // Create headers with session cookie
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", get_session_cookie_name(), session_id))
                .unwrap(),
        );

        // Create an invalid page token
        let invalid_token = "invalid_token".to_string();

        // Test verification failure with invalid token using global store
        let result = verify_page_session_token(&headers, Some(&invalid_token)).await;

        assert!(result.is_err());
        if let Err(SessionError::PageSessionToken(msg)) = result {
            assert!(msg.contains("does not match"));
        } else {
            panic!("Expected PageSessionToken error");
        }
    }

    /// Test verifying a page session token with a missing token
    /// This test verifies that page session token verification handles missing tokens correctly.
    /// It performs the following steps:
    /// 1. Stores valid session with CSRF token in cache
    /// 2. Creates HTTP headers with session cookie but without page session token
    /// 3. Calls verify_page_session_token and confirms it fails with appropriate error
    #[tokio::test]
    async fn test_verify_page_session_token_missing_token() {
        use crate::storage::CacheData;
        use crate::test_utils::init_test_environment;
        use http::HeaderMap;
        use http::header::{COOKIE, HeaderValue};

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_012";
        let csrf_token = "csrf_token_exists";

        // Create test session data as JSON
        let session_json = create_test_session(csrf_token);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
        };

        // Store the session in the global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl("session", session_id, cache_data, 3600)
            .await
            .unwrap();

        // Create headers with session cookie
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", get_session_cookie_name(), session_id))
                .unwrap(),
        );

        // Test verification failure with missing token using global store
        let result = verify_page_session_token(&headers, None).await;

        assert!(result.is_err());
        if let Err(SessionError::PageSessionToken(msg)) = result {
            assert!(msg.contains("missing"));
        } else {
            panic!("Expected PageSessionToken error");
        }
    }

    /// Test verifying a page session token with a missing session
    /// This test verifies that page session token verification handles missing sessions correctly.
    /// It performs the following steps:
    /// 1. Creates HTTP headers without any session cookie
    /// 2. Attempts to verify page session token without valid session context
    /// 3. Confirms that verification fails with "Session ID missing" error
    #[tokio::test]
    async fn test_verify_page_session_token_missing_session() {
        use crate::test_utils::init_test_environment;
        use http::HeaderMap;

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        // Create headers with no session cookie
        let headers = HeaderMap::new();

        // Generate some token
        let page_token = "some_token".to_string();

        // Test verification failure with missing session using global store
        let result = verify_page_session_token(&headers, Some(&page_token)).await;

        assert!(result.is_err());
        if let Err(SessionError::PageSessionToken(msg)) = result {
            assert!(msg.contains("Session ID missing"));
        } else {
            panic!("Expected PageSessionToken error");
        }
    }
}
