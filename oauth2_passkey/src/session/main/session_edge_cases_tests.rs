//! Edge case tests for the session module

#[cfg(test)]
mod edge_cases {
    use super::super::session::*;
    use super::super::test_utils::*;
    use crate::SESSION_COOKIE_NAME;
    use crate::session::errors::SessionError;
    use crate::session::types::StoredSession;
    use crate::storage::{CacheData, GENERIC_CACHE_STORE};
    use crate::test_utils::init_test_environment;
    use chrono::{Duration, Utc};
    use http::{HeaderMap, Method};
    use serial_test::serial;

    /// Test expired session with a direct manipulation of the expiration time
    /// This test verifies that the system correctly handles sessions that are already expired.
    /// It performs the following steps:
    /// 1. Creates session with expiration time set to 1 hour in the past
    /// 2. Stores the expired session directly in cache
    /// 3. Verifies that authentication fails and expired session is detected and handled
    #[tokio::test]
    async fn test_expired_session_direct() {
        init_test_environment().await;

        let session_id = "test_expired_session_direct";
        let user_id = "test_user_expired_direct";
        let csrf_token = "csrf_token_expired";

        // Create a session that is already expired (1 hour in the past)
        let expires_at = Utc::now() - Duration::hours(1);

        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: csrf_token.to_string(),
            expires_at,
            ttl: 3600,
        };

        // Store the expired session directly
        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put("session", session_id, cache_data)
            .await
            .unwrap();

        // Test expired session handling in get_csrf_token_from_session
        let result = get_csrf_token_from_session(session_id).await;
        assert!(result.is_err());
        match result {
            Err(SessionError::SessionExpiredError) => {} // Expected error
            other => panic!(
                "Expected SessionError::SessionExpiredError, got: {:?}",
                other
            ),
        }

        // Verify the expired session was removed
        let check_session = GENERIC_CACHE_STORE
            .lock()
            .await
            .get("session", session_id)
            .await
            .unwrap();
        assert!(check_session.is_none());
    }

    /// Test malformed session data
    /// This test verifies that the system correctly handles malformed session data in cache.
    /// It performs the following steps:
    /// 1. Stores invalid JSON data in cache (intentionally malformed session)
    /// 2. Attempts to retrieve CSRF token from session with malformed data
    /// 3. Verifies that the function returns appropriate Storage error for invalid JSON
    #[tokio::test]
    async fn test_malformed_session_data() {
        init_test_environment().await;

        let session_id = "malformed_session_data";

        // Create invalid JSON data
        let cache_data = CacheData {
            value: r#"{"user_id": "invalid_json"#.to_string(), // Intentionally malformed JSON
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put("session", session_id, cache_data)
            .await
            .unwrap();

        // Test error handling for malformed data in get_csrf_token_from_session
        let result = get_csrf_token_from_session(session_id).await;
        assert!(result.is_err());
        match result {
            Err(SessionError::Storage(_)) => {} // Expected error
            other => panic!("Expected SessionError::Storage, got: {:?}", other),
        }

        // Clean up
        let _ = delete_test_session(session_id).await;
    }

    /// Test missing fields in session data
    /// This test verifies that the system correctly handles session data with missing required fields.
    /// It performs the following steps:
    /// 1. Stores JSON session data missing required fields (csrf_token, expires_at, ttl)
    /// 2. Attempts to retrieve CSRF token from incomplete session data
    /// 3. Verifies that the function returns appropriate Storage error for missing fields
    #[tokio::test]
    async fn test_missing_fields_in_session() {
        init_test_environment().await;

        let session_id = "missing_fields_session";

        // Create JSON with missing fields
        let incomplete_json = r#"{"user_id": "test_user"}"#; // Missing csrf_token, expires_at, ttl
        let cache_data = CacheData {
            value: incomplete_json.to_string(),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put("session", session_id, cache_data)
            .await
            .unwrap();

        // Test error handling for missing fields
        let result = get_csrf_token_from_session(session_id).await;
        assert!(result.is_err());
        match result {
            Err(SessionError::Storage(_)) => {} // Expected error for missing fields
            other => panic!("Expected SessionError::Storage, got: {:?}", other),
        }

        // Clean up
        let _ = delete_test_session(session_id).await;
    }

    /// Test is_authenticated with CSRF protection - POST with missing CSRF token
    /// This test verifies that POST requests without CSRF tokens are properly rejected.
    /// It performs the following steps:
    /// 1. Creates valid user and session with CSRF token
    /// 2. Sends POST request with session cookie but missing CSRF token header
    /// 3. Verifies that authentication fails with CsrfToken error due to missing CSRF protection
    #[tokio::test]
    async fn test_is_authenticated_post_missing_csrf_token() {
        init_test_environment().await;

        // Create user and session
        let user_id = "user_missing_csrf";
        let csrf_token = "csrf_token_123";
        let session_id = "session_missing_csrf";

        let _ = create_test_user_and_session(
            user_id,
            "missing_csrf@example.com",
            "Missing CSRF",
            false,
            session_id,
            csrf_token,
            3600,
        )
        .await;

        // Create headers with session cookie but no CSRF token header
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );

        // Test with POST method - should fail due to missing CSRF token
        let result = is_authenticated_basic_then_csrf(&headers, &Method::POST).await;

        // Should return an error due to missing CSRF token
        assert!(result.is_err());
        match result {
            Err(SessionError::CsrfToken(_)) => {} // Expected error - session exists but CSRF fails
            other => panic!("Expected SessionError::CsrfToken, got: {:?}", other),
        }

        // Clean up
        let _ = cleanup_test_resources(user_id, session_id).await;
    }

    /// Test is_authenticated_strict_then_csrf
    /// This test verifies that strict authentication with CSRF validation works correctly.
    /// It performs the following steps:
    /// 1. Creates valid user and session with CSRF token
    /// 2. Tests POST request with correct CSRF token (should succeed)
    /// 3. Tests POST request with wrong CSRF token (should fail with CsrfToken error)
    #[tokio::test]
    #[serial]
    async fn test_is_authenticated_strict_then_csrf() {
        init_test_environment().await;

        // Create user and session
        let user_id = "user_strict_csrf_test";
        let csrf_token = "csrf_strict_token";
        let session_id = "session_strict_csrf";

        let _ = create_test_user_and_session(
            user_id,
            "strict_csrf@example.com",
            "Strict CSRF Test",
            false,
            session_id,
            csrf_token,
            3600,
        )
        .await;

        // Create headers with session cookie and matching CSRF token
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );
        headers.insert("X-CSRF-Token", csrf_token.parse().unwrap());

        // Test is_authenticated_strict_then_csrf - should succeed with valid user and CSRF
        let result = is_authenticated_strict_then_csrf(&headers, &Method::POST).await;
        assert!(result.is_ok());
        let (csrf_token_result, csrf_header_verified) = result.unwrap();

        // Verify correct results
        assert_eq!(csrf_token_result.as_str(), csrf_token);
        assert!(csrf_header_verified.0);

        // Test with invalid CSRF token
        let mut headers_invalid_csrf = HeaderMap::new();
        headers_invalid_csrf.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );
        headers_invalid_csrf.insert("X-CSRF-Token", "wrong_token".parse().unwrap());

        // Should fail due to CSRF mismatch
        let result = is_authenticated_strict_then_csrf(&headers_invalid_csrf, &Method::POST).await;
        assert!(result.is_err());
        match result {
            Err(SessionError::CsrfToken(_)) => {} // Expected error
            other => panic!("Expected SessionError::CsrfToken, got: {:?}", other),
        }

        // Clean up
        let _ = cleanup_test_resources(user_id, session_id).await;
    }

    /// Test is_authenticated_basic_then_user_and_csrf
    /// This test verifies that basic authentication followed by user and CSRF retrieval works correctly.
    /// It performs the following steps:
    /// 1. Creates valid user in database and session with CSRF token
    /// 2. Tests POST request with correct CSRF token and session
    /// 3. Verifies that user data, CSRF token, and CSRF header verification all return correctly
    #[tokio::test]
    #[serial]
    async fn test_is_authenticated_basic_then_user_and_csrf() {
        init_test_environment().await;

        // Create user and session
        let user_id = "basic_user_and_csrf";
        let account = "basic_csrf@example.com";
        let label = "Basic User and CSRF";
        let csrf_token = "basic_user_csrf_token";
        let session_id = "basic_user_csrf_session";

        let _ = create_test_user_and_session(
            user_id, account, label, false, session_id, csrf_token, 3600,
        )
        .await;

        // Create headers with session cookie and matching CSRF token
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );
        headers.insert("X-CSRF-Token", csrf_token.parse().unwrap());

        // Test is_authenticated_basic_then_user_and_csrf
        let result = is_authenticated_basic_then_user_and_csrf(&headers, &Method::POST).await;
        assert!(result.is_ok());
        let (user, csrf_token_result, csrf_header_verified) = result.unwrap();

        // Verify correct user and token were retrieved
        assert_eq!(user.id, user_id);
        assert_eq!(user.account, account);
        assert_eq!(user.label, label);
        assert_eq!(csrf_token_result.as_str(), csrf_token);
        assert!(csrf_header_verified.0);

        // Clean up
        let _ = cleanup_test_resources(user_id, session_id).await;
    }
}
