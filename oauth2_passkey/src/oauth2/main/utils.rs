use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use http::header::HeaderMap;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

use crate::oauth2::{OAuth2Error, OAuth2Mode, StateParams, StoredToken};

use crate::session::{
    User as SessionUser, delete_session_from_store_by_session_id, get_user_from_session,
};
use crate::storage::{
    CacheErrorConversion, CacheKey, CachePrefix, get_data, remove_data, store_cache_auto,
};

use crate::utils::gen_random_string_with_entropy_validation;

pub(super) fn encode_state(state_params: StateParams) -> Result<String, OAuth2Error> {
    let state_json =
        serde_json::to_string(&state_params).map_err(|e| OAuth2Error::Serde(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(state_json))
}

pub(crate) fn decode_state(state: &str) -> Result<StateParams, OAuth2Error> {
    let decoded_bytes = URL_SAFE_NO_PAD
        .decode(state)
        .map_err(|e| OAuth2Error::DecodeState(format!("Failed to decode base64: {e}")))?;
    let decoded_state_string = String::from_utf8(decoded_bytes)
        .map_err(|e| OAuth2Error::DecodeState(format!("Failed to decode UTF-8: {e}")))?;
    let state_in_response: StateParams = serde_json::from_str(&decoded_state_string)
        .map_err(|e| OAuth2Error::Serde(e.to_string()))?;
    Ok(state_in_response)
}

pub(super) async fn generate_store_token(
    token_type: &str,
    ttl: u64,
    expires_at: DateTime<Utc>,
    user_agent: Option<String>,
) -> Result<(String, String), OAuth2Error> {
    let token = gen_random_string_with_entropy_validation(32)?;

    let stored_token = StoredToken {
        token: token.clone(),
        expires_at,
        user_agent,
        ttl,
    };

    let cache_prefix =
        CachePrefix::new(token_type.to_string()).map_err(OAuth2Error::convert_storage_error)?;

    let token_id = store_cache_auto::<_, OAuth2Error>(cache_prefix, stored_token, ttl).await?;

    Ok((token, token_id))
}

pub(crate) async fn validate_origin(
    headers: &HeaderMap,
    auth_url: &str,
) -> Result<(), OAuth2Error> {
    let parsed_url = Url::parse(auth_url).expect("Invalid URL");
    let scheme = parsed_url.scheme();
    let host = parsed_url.host_str().unwrap_or_default();
    let port = parsed_url
        .port()
        .map_or("".to_string(), |p| format!(":{p}"));
    let expected_origin = format!("{scheme}://{host}{port}");

    let origin = headers
        .get("Origin")
        .or_else(|| headers.get("Referer"))
        .and_then(|h| h.to_str().ok());

    match origin {
        Some(origin) if origin.starts_with(&expected_origin) => Ok(()),
        _ => {
            tracing::error!("Expected Origin: {:#?}", expected_origin);
            tracing::error!("Actual Origin: {:#?}", origin);
            Err(OAuth2Error::InvalidOrigin(format!(
                "Expected Origin: {expected_origin:#?}, Actual Origin: {origin:#?}"
            )))
        }
    }
}

/// Creates a configured HTTP client for OAuth2 operations with the following settings:
///
/// - `timeout`: Set to 30 seconds to prevent indefinite hanging of requests.
///   OAuth2 operations should complete quickly, and hanging requests could block resources.
///
/// - `pool_idle_timeout`: Set to default (90 seconds). This controls how long an idle
///   connection can stay in the connection pool before being removed.
///
/// - `pool_max_idle_per_host`: Set to 32 (default). This controls the maximum number of idle
///   connections that can be maintained per host in the connection pool. The default value
///   provides good balance for parallel OAuth2 operations while being memory efficient.
pub(super) fn get_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(32)
        .build()
        .expect("Failed to create reqwest client")
}

/// Extract user ID from a stored session if it exists in the state parameters.
/// Returns None if:
/// - No misc_id in state parameters
/// - Session not found in cache
/// - Error getting user from session
pub(crate) async fn get_uid_from_stored_session_by_state_param(
    state_params: &StateParams,
) -> Result<Option<SessionUser>, OAuth2Error> {
    let Some(misc_id) = &state_params.misc_id else {
        tracing::debug!("No misc_id in state");
        return Ok(None);
    };

    tracing::debug!("misc_id: {:#?}", misc_id);

    let misc_cache_key = match CacheKey::new(misc_id.clone()) {
        Ok(key) => key,
        Err(e) => {
            tracing::debug!("Failed to create cache key: {}", e);
            return Ok(None);
        }
    };
    let Ok(Some(token)) =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::misc_session(), misc_cache_key).await
    else {
        tracing::debug!("Failed to get session from cache");
        return Ok(None);
    };

    tracing::debug!("Token: {:#?}", token);

    // Clean up the misc session after use
    // remove_token_from_store("misc_session", misc_id).await?;

    match get_user_from_session(&token.token).await {
        Ok(user) => {
            tracing::debug!("Found user ID: {}", user.id);
            Ok(Some(user))
        }
        Err(e) => {
            tracing::debug!("Failed to get user from session: {}", e);
            Ok(None)
        }
    }
}

pub(crate) async fn delete_session_and_misc_token_from_store(
    state_params: &StateParams,
) -> Result<(), OAuth2Error> {
    if let Some(misc_id) = &state_params.misc_id {
        let misc_cache_key = match CacheKey::new(misc_id.clone()) {
            Ok(key) => key,
            Err(e) => {
                tracing::debug!("Failed to create cache key: {}", e);
                return Ok(());
            }
        };
        let Ok(Some(token)) = get_data::<StoredToken, OAuth2Error>(
            CachePrefix::misc_session(),
            misc_cache_key.clone(),
        )
        .await
        else {
            tracing::debug!("Failed to get session from cache");
            return Ok(());
        };

        delete_session_from_store_by_session_id(&token.token)
            .await
            .map_err(|e| OAuth2Error::Storage(e.to_string()))?;

        remove_data::<OAuth2Error>(CachePrefix::misc_session(), misc_cache_key).await?;
    }

    Ok(())
}

pub(crate) async fn get_mode_from_stored_session(
    mode_id: &str,
) -> Result<Option<OAuth2Mode>, OAuth2Error> {
    let mode_cache_key = match CacheKey::new(mode_id.to_string()) {
        Ok(key) => key,
        Err(e) => {
            tracing::debug!("Failed to create cache key: {}", e);
            return Ok(None);
        }
    };
    let Ok(Some(token)) =
        get_data::<StoredToken, OAuth2Error>(CachePrefix::mode(), mode_cache_key).await
    else {
        tracing::debug!("Failed to get mode from cache");
        return Ok(None);
    };

    // Convert the string to OAuth2Mode enum
    match OAuth2Mode::from_str(&token.token) {
        Ok(mode) => Ok(Some(mode)),
        Err(_) => {
            tracing::warn!("Invalid mode value in cache: {}", token.token);
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::CacheData;
    use http::HeaderValue;

    // Test helper function to replace the removed store_token_in_cache function
    async fn store_token_in_cache(
        token_type: &str,
        token: &str,
        ttl: u64,
        expires_at: DateTime<Utc>,
        user_agent: Option<String>,
    ) -> Result<String, OAuth2Error> {
        let stored_token = StoredToken {
            token: token.to_string(),
            expires_at,
            user_agent,
            ttl,
        };

        let cache_prefix =
            CachePrefix::new(token_type.to_string()).map_err(OAuth2Error::convert_storage_error)?;

        store_cache_auto::<_, OAuth2Error>(cache_prefix, stored_token, ttl).await
    }

    /// Test state parameter encoding and decoding roundtrip
    ///
    /// This test verifies that StateParams can be encoded to base64url format and decoded back
    /// to the original values, ensuring the serialization roundtrip maintains data integrity.
    /// It creates a StateParams object in memory with all fields populated, encodes it,
    /// validates the base64url format, then decodes and verifies all fields match.
    ///
    #[test]
    fn test_encode_decode_state() {
        // Create a state params object with all fields populated
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: Some("misc123".to_string()),
            mode_id: Some("mode456".to_string()),
        };

        // Encode the state
        let encoded = encode_state(state_params).unwrap();

        // Verify the encoded state is a valid base64url string
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        // Decode the state
        let decoded = decode_state(&encoded).unwrap();

        // Verify all fields match the original
        assert_eq!(decoded.csrf_id, "csrf123");
        assert_eq!(decoded.nonce_id, "nonce456");
        assert_eq!(decoded.pkce_id, "pkce789");
        assert_eq!(decoded.misc_id, Some("misc123".to_string()));
        assert_eq!(decoded.mode_id, Some("mode456".to_string()));
    }

    /// Test state parameter encoding and decoding with minimal fields
    ///
    /// This test verifies that StateParams encoding and decoding works correctly when only
    /// required fields are populated and optional fields are None. It creates a StateParams
    /// object in memory with minimal data, encodes it to base64url, decodes it back, and
    /// verifies all fields including the None values are preserved correctly.
    ///
    #[test]
    fn test_encode_decode_state_minimal() {
        // Create a state params object with only required fields
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: None,
            mode_id: None,
        };

        // Encode the state
        let encoded = encode_state(state_params).unwrap();

        // Decode the state
        let decoded = decode_state(&encoded).unwrap();

        // Verify all fields match the original
        assert_eq!(decoded.csrf_id, "csrf123");
        assert_eq!(decoded.nonce_id, "nonce456");
        assert_eq!(decoded.pkce_id, "pkce789");
        assert_eq!(decoded.misc_id, None);
        assert_eq!(decoded.mode_id, None);
    }

    /// Test state decoding with invalid base64 input
    ///
    /// This test verifies that `decode_state` returns an appropriate OAuth2Error::DecodeState
    /// when given a string that contains invalid base64 characters. It attempts to decode
    /// an invalid base64 string and verifies that the correct error type is returned.
    ///
    #[test]
    fn test_decode_state_invalid_base64() {
        // Try to decode an invalid base64 string
        let result = decode_state("this is not base64!!!");

        // Verify it returns an error
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            Ok(_) => {
                unreachable!("Expected DecodeState error but got Ok");
            }
            Err(err) => {
                unreachable!("Expected DecodeState error, got {:?}", err);
            }
        }
    }

    /// Test state decoding with invalid JSON payload
    ///
    /// This test verifies that `decode_state` returns an appropriate OAuth2Error::DecodeState
    /// when given valid base64 that contains invalid JSON. It encodes invalid JSON as base64,
    /// attempts to decode it as state, and verifies that the correct error type is returned.
    ///
    #[test]
    fn test_decode_state_invalid_json() {
        // Encode some invalid JSON
        let invalid_json = "not valid json";
        let encoded = URL_SAFE_NO_PAD.encode(invalid_json);

        // Try to decode it
        let result = decode_state(&encoded);

        // Verify it returns an error
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::Serde(_)) => {}
            Ok(_) => {
                unreachable!("Expected Serde error but got Ok");
            }
            Err(err) => {
                unreachable!("Expected Serde error, got {:?}", err);
            }
        }
    }

    /// Test successful origin validation with matching origin header
    ///
    /// This test verifies that `validate_origin` succeeds when the Origin header
    /// in the request matches the expected origin derived from the callback URL.
    /// It creates HTTP headers with a matching origin and validates against a
    /// callback URL from the same origin.
    ///
    #[tokio::test]
    async fn test_validate_origin_success() {
        // Create headers with matching origin
        let mut headers = HeaderMap::new();
        headers.insert("Origin", HeaderValue::from_static("https://example.com"));

        // Validate against matching URL
        let result = validate_origin(&headers, "https://example.com/oauth2/callback").await;

        // Should succeed
        assert!(result.is_ok());
    }

    /// Test origin validation fallback to Referer header
    ///
    /// This test verifies that `validate_origin` can successfully validate using the
    /// Referer header when no Origin header is present. It creates HTTP headers with
    /// only a Referer header and validates that the origin is correctly extracted
    /// from the referer URL and matches the expected callback URL origin.
    ///
    #[tokio::test]
    async fn test_validate_origin_with_referer() {
        // Create headers with matching referer but no origin
        let mut headers = HeaderMap::new();
        headers.insert(
            "Referer",
            HeaderValue::from_static("https://example.com/login"),
        );

        // Validate against matching URL
        let result = validate_origin(&headers, "https://example.com/oauth2/callback").await;

        // Should succeed
        assert!(result.is_ok());
    }

    /// Tests for validate_origin with mismatched origin
    ///
    /// This test verifies that `validate_origin` correctly validates an origin
    /// when given a valid origin. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test origin directly in the database
    /// 3. Calls `validate_origin` to validate the origin
    /// 4. Verifies that the origin was successfully validated
    ///
    #[tokio::test]
    async fn test_validate_origin_mismatch() {
        // Create headers with non-matching origin
        let mut headers = HeaderMap::new();
        headers.insert("Origin", HeaderValue::from_static("https://attacker.com"));

        // Validate against different URL
        let result = validate_origin(&headers, "https://example.com/oauth2/callback").await;

        // Should fail
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::InvalidOrigin(_)) => {}
            Ok(_) => {
                unreachable!("Expected InvalidOrigin error but got Ok");
            }
            Err(err) => {
                unreachable!("Expected InvalidOrigin error, got {:?}", err);
            }
        }
    }

    /// Tests for validate_origin with missing origin
    ///
    /// This test verifies that `validate_origin` correctly validates an origin
    /// when given a valid origin. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test origin directly in the database
    /// 3. Calls `validate_origin` to validate the origin
    /// 4. Verifies that the origin was successfully validated
    ///
    #[tokio::test]
    async fn test_validate_origin_missing() {
        // Create headers with no origin or referer
        let headers = HeaderMap::new();

        // Validate against URL
        let result = validate_origin(&headers, "https://example.com/oauth2/callback").await;

        // Should fail
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::InvalidOrigin(_)) => {}
            Ok(_) => {
                unreachable!("Expected InvalidOrigin error but got Ok");
            }
            Err(err) => {
                unreachable!("Expected InvalidOrigin error, got {:?}", err);
            }
        }
    }

    /// Test token storage and retrieval roundtrip in cache
    ///
    /// This test verifies that tokens can be stored in the cache system and then successfully
    /// retrieved with all metadata intact. It configures an in-memory cache, stores a token
    /// with TTL and user agent information, retrieves it, and validates that all fields
    /// including expiration time are preserved correctly.
    ///
    #[tokio::test]
    async fn test_store_and_get_token_from_cache() {
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};
        init_test_environment().await;

        // Create test data
        let token_type = "test_token";
        let token = "test_token_value_12345";
        let ttl = 300; // 5 minutes
        let expires_at = Utc::now() + Duration::seconds(ttl as i64);
        let user_agent = Some("Test User Agent".to_string());

        // Store the token
        let result =
            store_token_in_cache(token_type, token, ttl, expires_at, user_agent.clone()).await;
        assert!(result.is_ok(), "Should successfully store token");
        let token_id = result.unwrap();

        // Verify token_id is generated (should be non-empty and deterministic length based on base64url encoding of 32 bytes)
        assert!(!token_id.is_empty(), "Token ID should not be empty");
        // 32 bytes base64url encoded = approximately 43 characters
        assert_eq!(
            token_id.len(),
            43,
            "Token ID should be 43 characters long (32 bytes base64url encoded)"
        );

        // Retrieve the token
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let retrieved_result = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    OAuth2Error::SecurityTokenNotFound("test_type-session not found".to_string())
                })
            });
        assert!(
            retrieved_result.is_ok(),
            "Should successfully retrieve token"
        );

        let stored_token = retrieved_result.unwrap();
        assert_eq!(stored_token.token, token);
        assert_eq!(stored_token.user_agent, user_agent);
        assert_eq!(stored_token.ttl, ttl);

        // Verify expires_at is preserved (within 1 second tolerance)
        let time_diff = (stored_token.expires_at - expires_at).num_seconds();
        assert!(time_diff.abs() < 1, "Expiration time should be preserved");
    }

    /// Test get_token_from_store behavior when token doesn't exist
    ///
    /// This test verifies that `get_token_from_store` returns the appropriate SecurityTokenNotFound
    /// error when attempting to retrieve a token that doesn't exist in the cache. It configures
    /// an in-memory cache, attempts to retrieve a non-existent token, and validates that the
    /// correct error type and message are returned.
    ///
    #[tokio::test]
    async fn test_get_token_from_store_not_found() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Try to get a token that doesn't exist
        let cache_prefix = CachePrefix::new("test_type".to_string()).unwrap();
        let cache_key = CacheKey::new("nonexistent_id".to_string()).unwrap();
        let result = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    OAuth2Error::SecurityTokenNotFound("test-session not found".to_string())
                })
            });

        // Verify it returns SecurityTokenNotFound error
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(msg)) => {
                assert!(msg.contains("test-session not found"));
            }
            Ok(_) => {
                unreachable!("Expected SecurityTokenNotFound error but got Ok");
            }
            Err(err) => {
                unreachable!("Expected SecurityTokenNotFound error, got {:?}", err);
            }
        }
    }

    /// Test token removal from cache store using direct cache API
    ///
    /// This test verifies that `remove_data` can successfully remove a token
    /// from the cache. It configures an in-memory cache, stores a token, verifies it exists,
    /// removes it, and then confirms the token is no longer retrievable, returning the
    /// appropriate SecurityTokenNotFound error.
    ///
    #[tokio::test]
    async fn test_remove_token_from_store() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_remove";
        let token_value = "test_token_value";
        let ttl = 300; // 5 minutes
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = Some("test-agent".to_string());

        // Store a token first
        let token_id =
            store_token_in_cache(token_type, token_value, ttl, expires_at, user_agent.clone())
                .await
                .unwrap();

        // Verify the token was stored
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let stored_token = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_token.token, token_value);

        // Remove the token
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let result = remove_data::<OAuth2Error>(cache_prefix, cache_key).await;
        assert!(result.is_ok());

        // Verify the token is no longer available
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let get_result = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .and_then(|opt| {
                opt.ok_or_else(|| {
                    OAuth2Error::SecurityTokenNotFound("test-session not found".to_string())
                })
            });
        assert!(get_result.is_err());
        match get_result {
            Err(OAuth2Error::SecurityTokenNotFound(_)) => {}
            Ok(_) => {
                unreachable!("Expected SecurityTokenNotFound error after removal but got Ok");
            }
            Err(err) => {
                unreachable!(
                    "Expected SecurityTokenNotFound error after removal, got {:?}",
                    err
                );
            }
        }
    }

    /// Test token generation and storage functionality
    ///
    /// This test verifies that `generate_store_token` can generate a secure random token,
    /// store it in the cache with metadata, and return both the token and token ID.
    /// It validates that both generated values have the expected length, are different
    /// from each other, and that the stored token can be retrieved with correct metadata.
    ///
    #[tokio::test]
    async fn test_generate_store_token() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_generate";
        let ttl = 600; // 10 minutes
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = Some("test-generate-agent".to_string());

        // Generate and store a token
        let result = generate_store_token(token_type, ttl, expires_at, user_agent.clone()).await;
        assert!(result.is_ok());

        let (token, token_id) = result.unwrap();

        // Verify both token and token_id are generated with expected lengths
        assert_eq!(
            token.len(),
            43,
            "Generated token should be 43 characters long"
        );
        assert_eq!(
            token_id.len(),
            43,
            "Generated token_id should be 43 characters long"
        );

        // Verify token and token_id are different
        assert_ne!(token, token_id, "Token and token_id should be different");

        // Verify the token can be retrieved from storage
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let stored_token = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored_token.token, token);
        assert_eq!(stored_token.user_agent, user_agent);
        assert_eq!(stored_token.ttl, ttl);

        // Verify expires_at is preserved (within 1 second tolerance)
        let time_diff = (stored_token.expires_at - expires_at).num_seconds();
        assert!(time_diff.abs() < 1, "Expiration time should be preserved");
    }

    /// Test token generation randomness and uniqueness
    ///
    /// This test verifies that `generate_store_token` generates unique, random tokens
    /// on each invocation. It generates multiple tokens and validates that all generated
    /// tokens and token IDs are unique, ensuring the cryptographic randomness is working
    /// correctly and preventing token collisions.
    ///
    #[tokio::test]
    async fn test_generate_store_token_randomness() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_randomness";
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = None;

        // Generate multiple tokens to verify randomness
        let (token1, token_id1) =
            generate_store_token(token_type, ttl, expires_at, user_agent.clone())
                .await
                .unwrap();
        let (token2, token_id2) =
            generate_store_token(token_type, ttl, expires_at, user_agent.clone())
                .await
                .unwrap();

        // Verify tokens are different (randomness check)
        assert_ne!(token1, token2, "Generated tokens should be different");
        assert_ne!(
            token_id1, token_id2,
            "Generated token IDs should be different"
        );

        // Verify both tokens can be retrieved independently
        let cache_prefix1 = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key1 = CacheKey::new(token_id1.clone()).unwrap();
        let cache_prefix2 = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key2 = CacheKey::new(token_id2.clone()).unwrap();
        let stored_token1 = get_data::<StoredToken, OAuth2Error>(cache_prefix1, cache_key1)
            .await
            .unwrap()
            .unwrap();
        let stored_token2 = get_data::<StoredToken, OAuth2Error>(cache_prefix2, cache_key2)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(stored_token1.token, token1);
        assert_eq!(stored_token2.token, token2);
    }

    /// Test get_uid_from_stored_session behavior when misc_id is None
    ///
    /// This test verifies that `get_uid_from_stored_session_by_state_param` returns Ok(None)
    /// when the StateParams has no misc_id field set. It creates StateParams without a misc_id
    /// and validates that the function correctly handles this case by returning None rather
    /// than attempting to retrieve a session.
    ///
    #[tokio::test]
    async fn test_get_uid_from_stored_session_no_misc_id() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Create state params without misc_id
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: None,
            mode_id: None,
        };

        // Call the function
        let result = get_uid_from_stored_session_by_state_param(&state_params).await;

        // Should return Ok(None) when misc_id is None
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Test get_uid_from_stored_session behavior when token is not found
    ///
    /// This test verifies that `get_uid_from_stored_session_by_state_param` returns Ok(None)
    /// when the misc_id token doesn't exist in the cache. It configures an in-memory cache,
    /// creates StateParams with a misc_id that doesn't correspond to any stored token,
    /// and validates that the function handles the missing token gracefully.
    ///
    #[tokio::test]
    async fn test_get_uid_from_stored_session_token_not_found() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Create state params with misc_id pointing to non-existent token
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: Some("nonexistent_misc_id".to_string()),
            mode_id: None,
        };

        // Call the function
        let result = get_uid_from_stored_session_by_state_param(&state_params).await;

        // Should return Ok(None) when token is not found in cache
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Test delete_session_and_misc_token behavior when misc_id is None
    ///
    /// This test verifies that `delete_session_and_misc_token_from_store` successfully returns
    /// Ok(()) when the StateParams has no misc_id field set. It creates StateParams without
    /// a misc_id and validates that the function handles this case gracefully without attempting
    /// to delete a non-existent token.
    ///
    #[tokio::test]
    async fn test_delete_session_and_misc_token_no_misc_id() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Create state params without misc_id
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: None,
            mode_id: None,
        };

        // Call the function
        let result = delete_session_and_misc_token_from_store(&state_params).await;

        // Should return Ok(()) when misc_id is None
        assert!(result.is_ok());
    }

    /// Test delete_session_and_misc_token behavior when token doesn't exist
    ///
    /// This test verifies that `delete_session_and_misc_token_from_store` successfully returns
    /// Ok(()) even when the misc_id points to a non-existent token in the cache. It configures
    /// an in-memory cache, creates StateParams with a misc_id that doesn't exist, and validates
    /// that the function handles missing tokens gracefully.
    ///
    #[tokio::test]
    async fn test_delete_session_and_misc_token_token_not_found() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Create state params with misc_id pointing to non-existent token
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: Some("nonexistent_misc_id".to_string()),
            mode_id: None,
        };

        // Call the function
        let result = delete_session_and_misc_token_from_store(&state_params).await;

        // Should return Ok(()) when token is not found in cache (graceful handling)
        assert!(result.is_ok());
    }

    /// Tests for get_mode_from_stored_session_not_found
    ///
    /// This test verifies that `get_mode_from_stored_session_not_found` correctly retrieves a mode
    /// when given a valid mode. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test mode directly in the database
    /// 3. Calls `get_mode_from_stored_session_not_found` to retrieve the mode
    /// 4. Verifies that the mode was successfully retrieved
    ///
    #[tokio::test]
    async fn test_get_mode_from_stored_session_not_found() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        // Call the function with a non-existent mode_id
        let result = get_mode_from_stored_session("nonexistent_mode_id").await;

        // Should return Ok(None) when mode token is not found in cache
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Test successful mode retrieval from stored session
    ///
    /// This test verifies that `get_mode_from_stored_session` can successfully retrieve and
    /// parse an OAuth2Mode from the cache when given a valid mode token ID. It stores a
    /// mode token in the cache, retrieves it using the mode ID, and validates that the
    /// correct OAuth2Mode value is returned.
    ///
    #[tokio::test]
    async fn test_get_mode_from_stored_session_valid_mode() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let mode_type = "mode";
        let mode = OAuth2Mode::Login;
        let mode_value = mode.as_str(); // Use as_str() to get valid string representation
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = None;

        // Store a mode token
        let mode_id = store_token_in_cache(mode_type, mode_value, ttl, expires_at, user_agent)
            .await
            .unwrap();

        // Call the function
        let result = get_mode_from_stored_session(&mode_id).await;

        // Should return Ok(Some(OAuth2Mode::Login))
        assert!(result.is_ok());
        let retrieved_mode = result.unwrap();
        assert!(retrieved_mode.is_some());

        // Verify it's the correct mode using PartialEq
        assert_eq!(retrieved_mode.unwrap(), mode);
    }

    /// Test mode retrieval with invalid mode value
    ///
    /// This test verifies that `get_mode_from_stored_session` returns Ok(None) when the
    /// stored token contains an invalid OAuth2Mode value that cannot be parsed. It stores
    /// an invalid mode string in the cache, attempts to retrieve and parse it, and validates
    /// that the function handles the parsing failure gracefully.
    ///
    #[tokio::test]
    async fn test_get_mode_from_stored_session_invalid_mode() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let mode_type = "mode";
        let invalid_mode_value = "invalid_mode_value"; // Invalid OAuth2Mode value
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = None;

        // Store an invalid mode token
        let mode_id =
            store_token_in_cache(mode_type, invalid_mode_value, ttl, expires_at, user_agent)
                .await
                .unwrap();

        // Call the function
        let result = get_mode_from_stored_session(&mode_id).await;

        // Should return Ok(None) when mode value is invalid
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// Test token caching with zero TTL (immediate expiration)
    ///
    /// This test verifies that `store_token_in_cache` can handle tokens with zero TTL
    /// and immediate expiration times. It stores a token with zero TTL, retrieves it,
    /// and validates that the token is stored with the correct expiration metadata,
    /// even when already expired at storage time.
    ///
    #[tokio::test]
    async fn test_cache_token_with_zero_ttl() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_zero_ttl";
        let token = "test_token_zero_ttl";
        let ttl = 0; // Zero TTL
        let expires_at = Utc::now(); // Immediate expiration
        let user_agent = Some("test-agent".to_string());

        // Store token with zero TTL
        let result =
            store_token_in_cache(token_type, token, ttl, expires_at, user_agent.clone()).await;
        assert!(
            result.is_ok(),
            "Should successfully store token with zero TTL"
        );

        let token_id = result.unwrap();

        // Should still be able to retrieve it immediately (cache doesn't enforce TTL for memory store)
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let stored_token = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
        assert!(
            stored_token.is_ok(),
            "Should be able to retrieve token with zero TTL"
        );
        let token_data = stored_token.unwrap().unwrap();
        assert_eq!(token_data.ttl, 0);
        assert_eq!(token_data.token, token);
    }

    /// Test token caching with maximum realistic TTL
    ///
    /// This test verifies that `store_token_in_cache` can handle tokens with very large
    /// but realistic TTL values (1 year). It stores a token with maximum TTL, retrieves it,
    /// and validates that the system handles large TTL values gracefully without overflow
    /// or storage issues.
    ///
    #[tokio::test]
    async fn test_cache_token_with_max_ttl() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_max_ttl";
        let token = "test_token_max_ttl";
        // Use a realistic maximum TTL (1 year = 31,536,000 seconds)
        // instead of u64::MAX which causes chrono overflow
        let ttl = 31_536_000_u64; // 1 year in seconds
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = None;

        // Should handle large but realistic TTL values gracefully
        let result = store_token_in_cache(token_type, token, ttl, expires_at, user_agent).await;
        assert!(result.is_ok(), "Should handle realistic large TTL values");

        let token_id = result.unwrap();
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let stored_token = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
        assert!(stored_token.is_ok(), "Should retrieve token with large TTL");
        assert_eq!(stored_token.unwrap().unwrap().ttl, ttl);
    }

    /// Test concurrent token operations and thread safety
    ///
    /// This test verifies that the cache token operations are thread-safe when multiple
    /// concurrent operations are performed simultaneously. It spawns multiple tokio tasks
    /// that generate and store tokens concurrently, then validates that all operations
    /// complete successfully and all generated token IDs are unique.
    ///
    #[tokio::test]
    async fn test_concurrent_token_operations() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_concurrent";
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);

        // Perform concurrent token storage operations
        let handles = (0..10)
            .map(|i| {
                let user_agent = Some(format!("agent-{i}"));
                tokio::spawn(async move {
                    store_token_in_cache(
                        token_type,
                        &format!("token-{i}"),
                        ttl,
                        expires_at,
                        user_agent,
                    )
                    .await
                })
            })
            .collect::<Vec<_>>();

        // Wait for all operations to complete
        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await);
        }

        // Verify all operations succeeded
        let mut token_ids = Vec::new();
        for result in results {
            let token_id = result.unwrap().unwrap();
            token_ids.push(token_id);
        }

        // Verify all tokens are unique and can be retrieved
        for (i, token_id) in token_ids.iter().enumerate() {
            let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let stored_token = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
            assert!(stored_token.is_ok());

            let token_data = stored_token.unwrap().unwrap();
            assert_eq!(token_data.token, format!("token-{i}"));
            assert_eq!(token_data.user_agent, Some(format!("agent-{i}")));
        }

        // Verify all token IDs are unique
        let unique_count = token_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert_eq!(unique_count, 10, "All token IDs should be unique");
    }

    /// Test token storage with different type prefixes
    ///
    /// This test verifies that tokens can be stored and retrieved using different type prefixes
    /// (csrf, nonce, pkce, access, refresh) without conflicts. It stores the same token content
    /// under different prefixes, then retrieves each one to ensure proper namespace isolation
    /// and that all prefixes work correctly with the cache system.
    ///
    #[tokio::test]
    async fn test_token_storage_with_different_prefixes() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = Some("test-agent".to_string());

        // Store tokens with different prefixes but same token ID
        let token_prefixes = ["csrf", "nonce", "pkce", "access", "refresh"];
        let same_token_content = "same_token_content";

        let mut stored_tokens = Vec::new();

        for prefix in &token_prefixes {
            let token_id = store_token_in_cache(
                prefix,
                same_token_content,
                ttl,
                expires_at,
                user_agent.clone(),
            )
            .await
            .unwrap();
            stored_tokens.push((prefix, token_id));
        }

        // Verify each token can be retrieved with its respective prefix
        for (prefix, token_id) in &stored_tokens {
            let cache_prefix = CachePrefix::new(prefix.to_string()).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
            assert!(
                retrieved.is_ok(),
                "Should retrieve token for prefix: {prefix}"
            );

            let token_data = retrieved.unwrap().unwrap();
            assert_eq!(token_data.token, same_token_content);
            assert_eq!(token_data.user_agent, user_agent);
        }

        // Verify tokens with different prefixes don't interfere
        for (prefix1, token_id1) in &stored_tokens {
            for (prefix2, _) in &stored_tokens {
                if prefix1 != prefix2 {
                    // Trying to get token with wrong prefix should fail
                    let cache_prefix = CachePrefix::new(prefix2.to_string()).unwrap();
                    let cache_key = CacheKey::new(token_id1.clone()).unwrap();
                    let wrong_retrieval =
                        get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
                            .await
                            .and_then(|opt| {
                                opt.ok_or_else(|| {
                                    OAuth2Error::SecurityTokenNotFound(
                                        "token not found".to_string(),
                                    )
                                })
                            });
                    assert!(
                        wrong_retrieval.is_err(),
                        "Should not retrieve token for {prefix2} with {prefix1}'s token_id"
                    );
                }
            }
        }
    }

    /// Test token storage with edge case inputs
    ///
    /// This test verifies that the token storage system handles edge cases gracefully,
    /// including empty token content, very long token values, and special characters.
    /// It tests the robustness of the storage and retrieval mechanisms with various
    /// boundary conditions and unusual but valid inputs.
    ///
    #[tokio::test]
    async fn test_token_storage_edge_cases() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);

        // Test with empty token content
        let empty_token_result = store_token_in_cache("test", "", ttl, expires_at, None).await;
        assert!(
            empty_token_result.is_ok(),
            "Should handle empty token content"
        );

        if let Ok(token_id) = empty_token_result {
            let cache_prefix = CachePrefix::new("test".to_string()).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
            assert!(retrieved.is_ok());
            assert_eq!(retrieved.unwrap().unwrap().token, "");
        }

        // Test with very long token content
        let long_token = "a".repeat(10000); // 10KB token
        let long_token_result =
            store_token_in_cache("test_long", &long_token, ttl, expires_at, None).await;
        assert!(
            long_token_result.is_ok(),
            "Should handle large token content"
        );

        if let Ok(token_id) = long_token_result {
            let cache_prefix = CachePrefix::new("test_long".to_string()).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
            assert!(retrieved.is_ok());
            assert_eq!(retrieved.unwrap().unwrap().token, long_token);
        }

        // Test with special characters in token
        let special_token = "token_with_特殊字符_🔐_\n\t\r";
        let special_result =
            store_token_in_cache("test_special", special_token, ttl, expires_at, None).await;
        assert!(
            special_result.is_ok(),
            "Should handle special characters in token"
        );

        if let Ok(token_id) = special_result {
            let cache_prefix = CachePrefix::new("test_special".to_string()).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
            assert!(retrieved.is_ok());
            assert_eq!(retrieved.unwrap().unwrap().token, special_token);
        }
    }

    /// Test token storage with independent token IDs
    ///
    /// This test verifies that storing multiple tokens of the same type generates
    /// independent token IDs rather than overwriting existing tokens. It stores two
    /// different tokens of the same type, validates that they receive different IDs,
    /// and confirms that both tokens can be independently retrieved with their
    /// respective content and metadata.
    ///
    #[tokio::test]
    async fn test_token_overwrite_same_id() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_overwrite";
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);

        // Store first token
        let token1 = "first_token";
        let user_agent1 = Some("agent1".to_string());
        let token_id1 =
            store_token_in_cache(token_type, token1, ttl, expires_at, user_agent1.clone())
                .await
                .unwrap();

        // Store second token
        let token2 = "second_token";
        let user_agent2 = Some("agent2".to_string());
        let token_id2 =
            store_token_in_cache(token_type, token2, ttl, expires_at, user_agent2.clone())
                .await
                .unwrap();

        // Verify both tokens exist independently (different IDs should be generated)
        assert_ne!(
            token_id1, token_id2,
            "Different tokens should have different IDs"
        );

        let cache_prefix1 = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key1 = CacheKey::new(token_id1.clone()).unwrap();
        let cache_prefix2 = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key2 = CacheKey::new(token_id2.clone()).unwrap();
        let retrieved1 = get_data::<StoredToken, OAuth2Error>(cache_prefix1, cache_key1)
            .await
            .unwrap()
            .unwrap();
        let retrieved2 = get_data::<StoredToken, OAuth2Error>(cache_prefix2, cache_key2)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(retrieved1.token, token1);
        assert_eq!(retrieved1.user_agent, user_agent1);
        assert_eq!(retrieved2.token, token2);
        assert_eq!(retrieved2.user_agent, user_agent2);
    }

    /// Test multiple remove operations on the same token
    ///
    /// This test verifies that the token removal system handles multiple removal attempts
    /// gracefully, including repeated removals of the same token and concurrent removal
    /// operations. It tests that the system doesn't fail when attempting to remove
    /// already-removed tokens and handles race conditions properly.
    ///
    #[tokio::test]
    async fn test_multiple_remove_operations() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_multiple_remove";
        let ttl = 300;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);

        // Store a token
        let token_id = store_token_in_cache(token_type, "test_token", ttl, expires_at, None)
            .await
            .unwrap();

        // Verify token exists
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
        assert!(retrieved.is_ok());

        // Remove the token
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let remove_result1 = remove_data::<OAuth2Error>(cache_prefix, cache_key).await;
        assert!(remove_result1.is_ok());

        // Verify token is gone
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let get_after_remove = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
            .await
            .and_then(|opt| {
                opt.ok_or_else(|| OAuth2Error::SecurityTokenNotFound("token not found".to_string()))
            });
        assert!(get_after_remove.is_err());

        // Try to remove the same token again (should handle gracefully)
        let cache_prefix2 = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key2 = CacheKey::new(token_id.clone()).unwrap();
        let remove_result2 = remove_data::<OAuth2Error>(cache_prefix2, cache_key2).await;
        assert!(remove_result2.is_ok(), "Second removal should not fail");

        // Try multiple concurrent removals of the same token
        let remove_handles = (0..5)
            .map(|_| {
                let token_id_clone = token_id.clone();
                let token_type_clone = token_type;
                tokio::spawn(async move {
                    let (cache_prefix, cache_key) = (
                        CachePrefix::new(token_type_clone.to_string()).unwrap(),
                        CacheKey::new(token_id_clone.clone()).unwrap(),
                    );
                    remove_data::<OAuth2Error>(cache_prefix, cache_key).await
                })
            })
            .collect::<Vec<_>>();

        let mut remove_results = Vec::new();
        for handle in remove_handles {
            remove_results.push(handle.await);
        }
        for result in remove_results {
            assert!(
                result.unwrap().is_ok(),
                "Concurrent removals should not fail"
            );
        }
    }

    /// Test cache operations with tokens that have past expiration times
    ///
    /// This test verifies that the cache system can handle tokens with expiration times
    /// set in the past. It stores a token with a past expiration time and validates that
    /// the token can still be stored and retrieved, while confirming that the expiration
    /// metadata is preserved correctly for potential cleanup operations.
    ///
    #[tokio::test]
    async fn test_cache_operations_with_past_expiration() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_past_expiration";
        let ttl = 300;
        // Set expiration time in the past
        let expires_at = Utc::now() - chrono::Duration::hours(1);

        // Store token with past expiration
        let token_id = store_token_in_cache(token_type, "expired_token", ttl, expires_at, None)
            .await
            .unwrap();

        // Should still be able to retrieve it (cache doesn't automatically expire in memory store)
        let cache_prefix = CachePrefix::new(token_type.to_string()).unwrap();
        let cache_key = CacheKey::new(token_id.clone()).unwrap();
        let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key).await;
        assert!(retrieved.is_ok());

        let token_data = retrieved.unwrap().unwrap();
        assert_eq!(token_data.token, "expired_token");
        // Verify the past expiration time is preserved
        assert!(token_data.expires_at < Utc::now());
    }

    /// Test cache serialization and deserialization roundtrip
    ///
    /// This test verifies that StoredToken objects can be properly serialized to CacheData
    /// and deserialized back while preserving all field values. It creates a complex token
    /// with various data types, performs the conversion roundtrip, and validates that all
    /// fields including timestamps and user agent strings are correctly preserved.
    ///
    #[tokio::test]
    async fn test_cache_serialization_round_trip() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let _token_type = "test_serialization";
        let ttl = 3600;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = Some("Mozilla/5.0 (Test) AppleWebKit/537.36".to_string());

        // Create a complex token with various data types
        let original_token = StoredToken {
            token: "complex_token_12345!@#$%".to_string(),
            expires_at,
            user_agent: user_agent.clone(),
            ttl,
        };

        // Convert to CacheData and back
        let cache_data = CacheData::from(original_token.clone());
        let recovered_token = StoredToken::try_from(cache_data);

        assert!(recovered_token.is_ok());
        let recovered = recovered_token.unwrap();

        // Verify all fields are preserved exactly
        assert_eq!(recovered.token, original_token.token);
        assert_eq!(
            recovered.expires_at.timestamp_millis(),
            original_token.expires_at.timestamp_millis()
        );
        assert_eq!(recovered.user_agent, original_token.user_agent);
        assert_eq!(recovered.ttl, original_token.ttl);
    }

    /// Test token generation consistency and behavior patterns
    ///
    /// This test verifies that `generate_store_token` produces consistent behavior across
    /// multiple invocations. It generates multiple tokens and validates that each generation
    /// produces tokens of consistent length, that all tokens are unique, and that the
    /// storage and retrieval process works reliably for each generated token.
    ///
    #[tokio::test]
    async fn test_generate_store_token_consistency() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let token_type = "test_consistency";
        let ttl = 600;
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl as i64);
        let user_agent = Some("consistency-test-agent".to_string());

        // Generate multiple tokens and verify consistency
        for i in 0..10 {
            let (token, token_id) = generate_store_token(
                &format!("{token_type}-{i}"),
                ttl,
                expires_at,
                user_agent.clone(),
            )
            .await
            .unwrap();

            // Verify token characteristics
            assert_eq!(token.len(), 43, "Generated token should be 43 characters");
            assert_eq!(
                token_id.len(),
                43,
                "Generated token ID should be 43 characters"
            );
            assert_ne!(token, token_id, "Token and token ID should be different");

            // Verify storage and retrieval
            let cache_prefix = CachePrefix::new(format!("{token_type}-{i}")).unwrap();
            let cache_key = CacheKey::new(token_id.clone()).unwrap();
            let retrieved = get_data::<StoredToken, OAuth2Error>(cache_prefix, cache_key)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(retrieved.token, token);
            assert_eq!(retrieved.user_agent, user_agent);
            assert_eq!(retrieved.ttl, ttl);

            // Verify expiration time consistency (within 1 second tolerance)
            let time_diff = (retrieved.expires_at - expires_at).num_seconds().abs();
            assert!(time_diff <= 1, "Expiration time should be consistent");
        }
    }
}
