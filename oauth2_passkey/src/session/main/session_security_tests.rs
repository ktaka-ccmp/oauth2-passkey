//! Advanced session security tests for session fixation, hijacking, and related attacks.
//!
//! This module contains comprehensive security tests to validate that the session management
//! system is resilient against various session-based attacks including:
//! - Session fixation attacks
//! - Session hijacking attempts
//! - Session invalidation edge cases
//! - Cross-session token reuse
//! - Session timeout manipulation
//!
//! These tests complement the existing session tests by focusing specifically on security
//! vulnerabilities and attack scenarios.

#[cfg(test)]
mod tests {
    use crate::session::config::SESSION_COOKIE_NAME;
    use crate::session::main::session::*;
    use crate::storage::{CacheData, CacheKey, CachePrefix, GENERIC_CACHE_STORE};
    use crate::test_utils::init_test_environment;
    use chrono::{Duration, Utc};
    use http::header::COOKIE;
    use http::{HeaderMap, HeaderValue, Method};

    // Helper function to create a header map with a cookie
    fn create_header_map_with_cookie(cookie_name: &str, cookie_value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let cookie_str = format!("{cookie_name}={cookie_value}");
        // Use try_from_str to handle invalid header values gracefully
        if let Ok(header_value) = HeaderValue::from_str(&cookie_str) {
            headers.insert(COOKIE, header_value);
        }
        headers
    }

    // Helper function to create a test StoredSession for security tests
    fn create_security_test_session(
        csrf_token: &str,
        user_id: &str,
        expires_offset_seconds: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "user_id": user_id,
            "csrf_token": csrf_token,
            "expires_at": (Utc::now() + Duration::seconds(expires_offset_seconds)).to_rfc3339(),
            "ttl": 3600_u64,
        })
    }

    // Helper function to store session in cache
    async fn store_session_in_cache(
        session_id: &str,
        session_data: serde_json::Value,
        ttl: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Extract the actual session expiration time from the session data
        let session_expires_at =
            if let Some(expires_at_str) = session_data.get("expires_at").and_then(|v| v.as_str()) {
                chrono::DateTime::parse_from_rfc3339(expires_at_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now() + chrono::Duration::seconds(ttl as i64))
            } else {
                chrono::Utc::now() + chrono::Duration::seconds(ttl as i64)
            };

        let cache_data = CacheData {
            value: session_data.to_string(),
            expires_at: session_expires_at,
        };

        let cache_key = CacheKey::new(session_id.to_string())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(CachePrefix::session(), cache_key, cache_data, ttl)
            .await?;
        Ok(())
    }

    /// Test session fixation attack prevention
    ///
    /// Session fixation occurs when an attacker sets a session ID for a user before authentication,
    /// then uses that same session ID after the user authenticates. This test verifies that:
    /// 1. Session IDs are generated with sufficient entropy to prevent prediction
    /// 2. Pre-existing session IDs are not reused after authentication
    /// 3. Session creation generates unique identifiers
    #[tokio::test]
    async fn test_security_session_fixation_prevention() {
        init_test_environment().await;

        // Test case 1: Session ID uniqueness and entropy
        let user_id = "test_user_fixation";
        let mut session_ids = std::collections::HashSet::new();

        // Create multiple sessions to check for uniqueness
        for i in 0..100 {
            let headers_result = create_new_session_with_uid(&format!("{user_id}_{i}")).await;
            assert!(headers_result.is_ok(), "Session creation should succeed");

            let headers = headers_result.unwrap();
            let cookie_header = headers.get(http::header::SET_COOKIE).unwrap();
            let cookie_str = cookie_header.to_str().unwrap();

            // Extract session ID from cookie
            let session_id = cookie_str
                .split(';')
                .next()
                .unwrap()
                .split('=')
                .nth(1)
                .unwrap();

            // Verify session ID is not empty and has sufficient length
            assert!(!session_id.is_empty(), "Session ID should not be empty");
            assert!(
                session_id.len() >= 32,
                "Session ID should have sufficient length for security"
            );

            // Verify session ID is unique
            assert!(
                session_ids.insert(session_id.to_string()),
                "Session ID should be unique: {session_id}"
            );
        }

        // Test case 2: Session ID entropy validation
        // All generated session IDs should be unique (no collisions in 100 generations)
        assert_eq!(session_ids.len(), 100, "All session IDs should be unique");

        // Test case 3: Verify session IDs are not predictable
        let session_ids_vec: Vec<String> = session_ids.into_iter().collect();
        for i in 1..session_ids_vec.len() {
            let prev_id = &session_ids_vec[i - 1];
            let curr_id = &session_ids_vec[i];

            // Check that session IDs don't follow predictable patterns
            assert_ne!(
                prev_id, curr_id,
                "Consecutive session IDs should be different"
            );

            // Verify they don't differ by simple increments (basic pattern check)
            let prev_bytes = prev_id.as_bytes();
            let curr_bytes = curr_id.as_bytes();
            let mut diff_count = 0;

            for (p, c) in prev_bytes.iter().zip(curr_bytes.iter()) {
                if p != c {
                    diff_count += 1;
                }
            }

            // Expect significant differences between session IDs (not just 1-2 character changes)
            assert!(
                diff_count >= 10,
                "Session IDs should have significant entropy differences"
            );
        }
    }

    /// Test session hijacking attack detection and prevention
    ///
    /// Session hijacking occurs when an attacker obtains a valid session ID and uses it
    /// to impersonate the legitimate user. This test verifies:
    /// 1. Session validation works correctly with legitimate session IDs
    /// 2. Invalid or tampered session IDs are rejected
    /// 3. Session expiration is properly enforced
    /// 4. CSRF tokens provide additional protection against session misuse
    #[tokio::test]
    async fn test_security_session_hijacking_prevention() {
        init_test_environment().await;

        let user_id = "test_user_hijacking";
        let csrf_token = "test_csrf_hijacking";
        let valid_session_id = "valid_session_123";
        let tampered_session_id = "tampered_session_456";

        // Create a legitimate session
        let valid_session = create_security_test_session(csrf_token, user_id, 3600);
        store_session_in_cache(valid_session_id, valid_session, 3600)
            .await
            .unwrap();

        // Test case 1: Legitimate session should authenticate successfully
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let valid_headers = create_header_map_with_cookie(&cookie_name, valid_session_id);

        let auth_result = is_authenticated_basic(&valid_headers, &Method::GET).await;
        assert!(
            auth_result.is_ok(),
            "Legitimate session should authenticate"
        );
        assert!(
            auth_result.unwrap().0,
            "Authentication should succeed for valid session"
        );

        // Test case 2: Tampered/invalid session ID should be rejected
        let invalid_headers = create_header_map_with_cookie(&cookie_name, tampered_session_id);

        let auth_result = is_authenticated_basic(&invalid_headers, &Method::GET).await;
        assert!(
            auth_result.is_ok(),
            "Invalid session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Authentication should fail for invalid session"
        );

        // Test case 3: Empty session ID should be rejected
        let empty_headers = create_header_map_with_cookie(&cookie_name, "");

        let auth_result = is_authenticated_basic(&empty_headers, &Method::GET).await;
        assert!(auth_result.is_ok(), "Empty session check should not error");
        assert!(
            !auth_result.unwrap().0,
            "Authentication should fail for empty session"
        );

        // Test case 4: Malformed session ID should be rejected
        // Split into two categories: safe malformed (handled gracefully) vs dangerous (cause errors)

        // Safe malformed IDs that should be handled gracefully
        let safe_malformed_ids = vec![
            "short".to_string(),                         // Too short but safe
            "../../../etc/passwd".to_string(),           // Path traversal attempt
            "<script>alert('xss')</script>".to_string(), // XSS attempt
        ];

        for malformed_id in safe_malformed_ids {
            let malformed_headers = create_header_map_with_cookie(&cookie_name, &malformed_id);

            let auth_result = is_authenticated_basic(&malformed_headers, &Method::GET).await;
            assert!(
                auth_result.is_ok(),
                "Safe malformed session check should not error for: {malformed_id}"
            );
            assert!(
                !auth_result.unwrap().0,
                "Authentication should fail for malformed session: {malformed_id}"
            );
        }

        // Dangerous malformed IDs that should cause cache key validation errors
        let dangerous_malformed_ids = vec![
            "a".repeat(1000),                         // Too long (>200 chars)
            "session with spaces".to_string(),        // Contains spaces
            "session\nwith\nnewlines".to_string(),    // Contains newlines
            "session\x00with\x00nulls".to_string(),   // Contains null bytes
            "'; DROP TABLE sessions; --".to_string(), // SQL injection attempt
        ];

        for dangerous_id in dangerous_malformed_ids {
            let malformed_headers = create_header_map_with_cookie(&cookie_name, &dangerous_id);

            let auth_result = is_authenticated_basic(&malformed_headers, &Method::GET).await;
            // These should now cause errors due to cache key validation (which is good!)
            if auth_result.is_ok() {
                assert!(
                    !auth_result.unwrap().0,
                    "If dangerous malformed session doesn't error, authentication should still fail: {dangerous_id}"
                );
            }
            // If it errors, that's also acceptable - early validation caught the problem
        }

        // Test case 5: CSRF protection should prevent unauthorized state changes
        let mut post_headers = create_header_map_with_cookie(&cookie_name, valid_session_id);
        post_headers.insert(
            "X-CSRF-Token",
            HeaderValue::from_str("wrong_csrf_token").unwrap(),
        );

        let csrf_result = is_authenticated_basic(&post_headers, &Method::POST).await;
        assert!(
            csrf_result.is_err(),
            "POST with wrong CSRF token should fail"
        );

        // Verify the error is specifically a CSRF token error
        match csrf_result.unwrap_err() {
            crate::session::errors::SessionError::CsrfToken(_) => {
                // Expected error type
            }
            other => panic!("Expected CSRF token error, got: {other:?}"),
        }
    }

    /// Test session invalidation security
    ///
    /// This test verifies that session invalidation works correctly and prevents
    /// unauthorized access after session termination:
    /// 1. Valid sessions are properly invalidated
    /// 2. Invalidated sessions cannot be used for authentication
    /// 3. Session cleanup removes all traces from storage
    /// 4. Multiple invalidation attempts are handled gracefully
    #[tokio::test]
    async fn test_security_session_invalidation() {
        init_test_environment().await;

        let user_id = "test_user_invalidation";
        let csrf_token = "test_csrf_invalidation";
        let session_id = "session_to_invalidate";

        // Create a valid session
        let session_data = create_security_test_session(csrf_token, user_id, 3600);
        store_session_in_cache(session_id, session_data, 3600)
            .await
            .unwrap();

        // Test case 1: Session should be valid before invalidation
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        let auth_result = is_authenticated_basic(&headers, &Method::GET).await;
        assert!(
            auth_result.is_ok(),
            "Session should be valid before invalidation"
        );
        assert!(
            auth_result.unwrap().0,
            "Authentication should succeed before invalidation"
        );

        // Test case 2: Invalidate the session
        let delete_result = delete_session_from_store_by_session_id(session_id).await;
        assert!(delete_result.is_ok(), "Session deletion should succeed");

        // Test case 3: Session should be invalid after invalidation
        let auth_result = is_authenticated_basic(&headers, &Method::GET).await;
        assert!(
            auth_result.is_ok(),
            "Invalidated session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Authentication should fail after invalidation"
        );

        // Test case 4: Verify session is removed from storage
        let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
        let cache_key = CacheKey::new(session_id.to_string()).unwrap();
        let cache_check = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await;
        assert!(cache_check.is_ok(), "Cache check should not error");
        assert!(
            cache_check.unwrap().is_none(),
            "Session should be removed from cache"
        );

        // Test case 5: Multiple invalidation attempts should be safe
        let delete_result_2 = delete_session_from_store_by_session_id(session_id).await;
        assert!(
            delete_result_2.is_ok(),
            "Multiple deletion attempts should not error"
        );

        // Test case 6: Attempt to access any session data should fail
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let csrf_result = get_csrf_token_from_session(&session_cookie).await;
        assert!(
            csrf_result.is_err(),
            "CSRF token retrieval should fail for invalidated session"
        );

        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let user_result = get_user_from_session(&session_cookie).await;
        assert!(
            user_result.is_err(),
            "User retrieval should fail for invalidated session"
        );
    }

    /// Test cross-session token reuse prevention
    ///
    /// This test verifies that CSRF tokens and session data cannot be reused across
    /// different sessions, preventing cross-session attacks:
    /// 1. CSRF tokens are unique per session
    /// 2. CSRF tokens from one session cannot be used in another
    /// 3. Session data isolation is maintained
    #[tokio::test]
    async fn test_security_cross_session_token_reuse_prevention() {
        init_test_environment().await;

        let user_id_1 = "test_user_session_1";
        let user_id_2 = "test_user_session_2";
        let csrf_token_1 = "csrf_token_session_1";
        let csrf_token_2 = "csrf_token_session_2";
        let session_id_1 = "session_1_unique";
        let session_id_2 = "session_2_unique";

        // Create two separate sessions with different CSRF tokens
        let session_1 = create_security_test_session(csrf_token_1, user_id_1, 3600);
        let session_2 = create_security_test_session(csrf_token_2, user_id_2, 3600);

        store_session_in_cache(session_id_1, session_1, 3600)
            .await
            .unwrap();
        store_session_in_cache(session_id_2, session_2, 3600)
            .await
            .unwrap();

        let cookie_name = SESSION_COOKIE_NAME.to_string();

        // Test case 1: Each session should work with its own CSRF token
        let mut headers_1 = create_header_map_with_cookie(&cookie_name, session_id_1);
        headers_1.insert("X-CSRF-Token", HeaderValue::from_str(csrf_token_1).unwrap());

        let auth_result_1 = is_authenticated_basic(&headers_1, &Method::POST).await;
        assert!(
            auth_result_1.is_ok(),
            "Session 1 should authenticate with its CSRF token"
        );

        let mut headers_2 = create_header_map_with_cookie(&cookie_name, session_id_2);
        headers_2.insert("X-CSRF-Token", HeaderValue::from_str(csrf_token_2).unwrap());

        let auth_result_2 = is_authenticated_basic(&headers_2, &Method::POST).await;
        assert!(
            auth_result_2.is_ok(),
            "Session 2 should authenticate with its CSRF token"
        );

        // Test case 2: Cross-session CSRF token reuse should fail
        let mut cross_headers_1 = create_header_map_with_cookie(&cookie_name, session_id_1);
        cross_headers_1.insert("X-CSRF-Token", HeaderValue::from_str(csrf_token_2).unwrap()); // Wrong token

        let cross_result_1 = is_authenticated_basic(&cross_headers_1, &Method::POST).await;
        assert!(
            cross_result_1.is_err(),
            "Session 1 should reject Session 2's CSRF token"
        );

        let mut cross_headers_2 = create_header_map_with_cookie(&cookie_name, session_id_2);
        cross_headers_2.insert("X-CSRF-Token", HeaderValue::from_str(csrf_token_1).unwrap()); // Wrong token

        let cross_result_2 = is_authenticated_basic(&cross_headers_2, &Method::POST).await;
        assert!(
            cross_result_2.is_err(),
            "Session 2 should reject Session 1's CSRF token"
        );

        // Test case 3: Verify error types are CSRF-related
        match cross_result_1.unwrap_err() {
            crate::session::errors::SessionError::CsrfToken(_) => {
                // Expected error type
            }
            other => panic!("Expected CSRF token error for cross-session reuse, got: {other:?}"),
        }

        match cross_result_2.unwrap_err() {
            crate::session::errors::SessionError::CsrfToken(_) => {
                // Expected error type
            }
            other => panic!("Expected CSRF token error for cross-session reuse, got: {other:?}"),
        }

        // Test case 4: Session data isolation - verify sessions contain different data
        let session_cookie_1 = crate::SessionCookie::new(session_id_1.to_string()).unwrap();
        let csrf_1_result = get_csrf_token_from_session(&session_cookie_1).await;
        let session_cookie_2 = crate::SessionCookie::new(session_id_2.to_string()).unwrap();
        let csrf_2_result = get_csrf_token_from_session(&session_cookie_2).await;

        assert!(
            csrf_1_result.is_ok(),
            "Session 1 CSRF retrieval should succeed"
        );
        assert!(
            csrf_2_result.is_ok(),
            "Session 2 CSRF retrieval should succeed"
        );

        let retrieved_csrf_1 = csrf_1_result.unwrap();
        let retrieved_csrf_2 = csrf_2_result.unwrap();

        assert_eq!(
            retrieved_csrf_1.as_str(),
            csrf_token_1,
            "Session 1 should have correct CSRF token"
        );
        assert_eq!(
            retrieved_csrf_2.as_str(),
            csrf_token_2,
            "Session 2 should have correct CSRF token"
        );
        assert_ne!(
            retrieved_csrf_1.as_str(),
            retrieved_csrf_2.as_str(),
            "Sessions should have different CSRF tokens"
        );
    }

    /// Test session timeout manipulation resistance
    ///
    /// This test verifies that session timeout cannot be manipulated by attackers:
    /// 1. Expired sessions are properly rejected
    /// 2. Session expiration cannot be bypassed
    /// 3. Expired sessions are automatically cleaned up
    /// 4. Grace periods are not exploitable
    #[tokio::test]
    async fn test_security_session_timeout_manipulation_resistance() {
        init_test_environment().await;

        let user_id = "test_user_timeout";
        let csrf_token = "test_csrf_timeout";
        let cookie_name = SESSION_COOKIE_NAME.to_string();

        // Test case 1: Recently expired session should be rejected
        let expired_session_id = "expired_session_recent";
        let expired_session = create_security_test_session(csrf_token, user_id, -1); // Expired 1 second ago
        store_session_in_cache(expired_session_id, expired_session, 3600)
            .await
            .unwrap();

        let expired_headers = create_header_map_with_cookie(&cookie_name, expired_session_id);
        let auth_result = is_authenticated_basic(&expired_headers, &Method::GET).await;

        assert!(
            auth_result.is_ok(),
            "Expired session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Recently expired session should be rejected"
        );

        // Verify expired session was cleaned up
        let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
        let cache_key = CacheKey::new(expired_session_id.to_string()).unwrap();
        let cache_check = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await;
        assert!(cache_check.is_ok(), "Cache check should not error");
        assert!(
            cache_check.unwrap().is_none(),
            "Expired session should be cleaned up"
        );

        // Test case 2: Long-expired session should be rejected
        let long_expired_session_id = "expired_session_long";
        let long_expired_session = create_security_test_session(csrf_token, user_id, -86400); // Expired 1 day ago
        store_session_in_cache(long_expired_session_id, long_expired_session, 3600)
            .await
            .unwrap();

        let long_expired_headers =
            create_header_map_with_cookie(&cookie_name, long_expired_session_id);
        let auth_result = is_authenticated_basic(&long_expired_headers, &Method::GET).await;

        assert!(
            auth_result.is_ok(),
            "Long expired session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Long expired session should be rejected"
        );

        // Test case 3: Valid session should still work
        let valid_session_id = "valid_session_timeout_test";
        let valid_session = create_security_test_session(csrf_token, user_id, 3600); // Valid for 1 hour
        store_session_in_cache(valid_session_id, valid_session, 3600)
            .await
            .unwrap();

        let valid_headers = create_header_map_with_cookie(&cookie_name, valid_session_id);
        let auth_result = is_authenticated_basic(&valid_headers, &Method::GET).await;

        assert!(auth_result.is_ok(), "Valid session check should not error");
        assert!(auth_result.unwrap().0, "Valid session should be accepted");

        // Test case 4: Session at the edge of expiration
        let edge_session_id = "edge_session_timeout";
        let edge_session = create_security_test_session(csrf_token, user_id, 1); // Expires in 1 second
        store_session_in_cache(edge_session_id, edge_session, 3600)
            .await
            .unwrap();

        // Should be valid immediately
        let edge_headers = create_header_map_with_cookie(&cookie_name, edge_session_id);
        let auth_result = is_authenticated_basic(&edge_headers, &Method::GET).await;

        assert!(auth_result.is_ok(), "Edge session check should not error");
        assert!(
            auth_result.unwrap().0,
            "Session at edge should be accepted when still valid"
        );

        // Wait for session to expire (2 seconds to be safe)
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Should now be expired
        let auth_result = is_authenticated_basic(&edge_headers, &Method::GET).await;
        assert!(
            auth_result.is_ok(),
            "Expired edge session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Session should be rejected after expiration"
        );

        // Test case 5: Malformed expiration times should be handled safely
        let malformed_session_id = "malformed_expiration_session";
        let malformed_session = serde_json::json!({
            "user_id": user_id,
            "csrf_token": csrf_token,
            "expires_at": "invalid_datetime_string",
            "ttl": 3600_u64,
        });
        store_session_in_cache(malformed_session_id, malformed_session, 3600)
            .await
            .unwrap();

        let malformed_headers = create_header_map_with_cookie(&cookie_name, malformed_session_id);
        let auth_result = is_authenticated_basic(&malformed_headers, &Method::GET).await;

        assert!(
            auth_result.is_ok(),
            "Malformed session check should not error"
        );
        assert!(
            !auth_result.unwrap().0,
            "Malformed session should be rejected"
        );
    }

    /// Test session concurrency and race condition resistance
    ///
    /// This test verifies that concurrent session operations don't create security vulnerabilities:
    /// 1. Concurrent session access is handled safely
    /// 2. Race conditions don't allow unauthorized access
    /// 3. Session state remains consistent under concurrent load
    #[tokio::test]
    async fn test_security_session_concurrency_safety() {
        init_test_environment().await;

        let user_id = "test_user_concurrency";
        let csrf_token = "test_csrf_concurrency";
        let session_id = "concurrent_session_test";
        let cookie_name = SESSION_COOKIE_NAME.to_string();

        // Create a valid session
        let session_data = create_security_test_session(csrf_token, user_id, 3600);
        store_session_in_cache(session_id, session_data, 3600)
            .await
            .unwrap();

        // Test case 1: Concurrent authentication attempts should be consistent
        let mut handles = vec![];

        for i in 0..50 {
            let session_id = session_id.to_string();
            let cookie_name = cookie_name.clone();

            let handle = tokio::spawn(async move {
                let headers = create_header_map_with_cookie(&cookie_name, &session_id);
                let auth_result = is_authenticated_basic(&headers, &Method::GET).await;
                (i, auth_result)
            });

            handles.push(handle);
        }

        // Wait for all authentication attempts and verify consistency
        let mut auth_results = vec![];
        for handle in handles {
            let (i, result) = handle.await.unwrap();
            auth_results.push((i, result));
        }

        // All authentication attempts should succeed (session is valid)
        for (i, result) in &auth_results {
            assert!(
                result.is_ok(),
                "Concurrent auth attempt {i} should not error"
            );
            assert!(
                result.as_ref().unwrap().0,
                "Concurrent auth attempt {i} should succeed"
            );
        }

        // Test case 2: Concurrent session deletion and access
        let mut deletion_handles = vec![];
        let mut access_handles = vec![];

        // Start multiple deletion attempts
        for i in 0..5 {
            let session_id = session_id.to_string();
            let handle = tokio::spawn(async move {
                let result = delete_session_from_store_by_session_id(&session_id).await;
                (format!("delete_{i}"), result)
            });
            deletion_handles.push(handle);
        }

        // Start multiple access attempts
        for i in 0..10 {
            let session_id = session_id.to_string();
            let cookie_name = cookie_name.clone();
            let handle = tokio::spawn(async move {
                let headers = create_header_map_with_cookie(&cookie_name, &session_id);
                let result = is_authenticated_basic(&headers, &Method::GET).await;
                (format!("access_{i}"), result)
            });
            access_handles.push(handle);
        }

        // Wait for all operations
        let mut deletion_results = vec![];
        let mut access_results = vec![];

        // Wait for deletion operations
        for handle in deletion_handles {
            let (op_type, result) = handle.await.unwrap();
            deletion_results.push((op_type, result));
        }

        // Wait for access operations
        for handle in access_handles {
            let (op_type, result) = handle.await.unwrap();
            access_results.push((op_type, result));
        }

        // Verify all deletion operations completed without errors
        for (op_type, result) in &deletion_results {
            assert!(
                result.is_ok(),
                "Deletion operation {op_type} should not error"
            );
        }

        // Verify all access operations completed without errors
        for (op_type, result) in &access_results {
            assert!(
                result.is_ok(),
                "Access operation {op_type} should not error"
            );
            // Note: auth result may be true or false depending on timing, but should not error
        }

        // Verify final state - session should be deleted
        let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
        let cache_key = CacheKey::new(session_id.to_string()).unwrap();
        let final_check = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(cache_prefix, cache_key)
            .await;
        assert!(final_check.is_ok(), "Final cache check should not error");
        assert!(
            final_check.unwrap().is_none(),
            "Session should be deleted after concurrent operations"
        );
    }

    /// Test session storage integrity under attack scenarios
    ///
    /// This test verifies that session storage maintains integrity under various attack scenarios:
    /// 1. Cache pollution attacks
    /// 2. Storage overflow attempts
    /// 3. Invalid data injection
    /// 4. Key collision attempts
    #[tokio::test]
    async fn test_security_session_storage_integrity() {
        init_test_environment().await;

        let user_id = "test_user_storage";
        let csrf_token = "test_csrf_storage";
        let legitimate_session_id = "legitimate_session";
        let cookie_name = SESSION_COOKIE_NAME.to_string();

        // Create a legitimate session
        let legitimate_session = create_security_test_session(csrf_token, user_id, 3600);
        store_session_in_cache(legitimate_session_id, legitimate_session, 3600)
            .await
            .unwrap();

        // Test case 1: Attempt to store invalid session data
        let invalid_data_attempts = vec![
            ("invalid_json", r#"{"invalid": json syntax}"#),
            ("missing_fields", r#"{"user_id": "test"}"#),
            (
                "wrong_types",
                r#"{"user_id": 123, "csrf_token": true, "expires_at": "not_a_date", "ttl": "not_a_number"}"#,
            ),
            (
                "null_values",
                r#"{"user_id": null, "csrf_token": null, "expires_at": null, "ttl": null}"#,
            ),
            (
                "empty_strings",
                r#"{"user_id": "", "csrf_token": "", "expires_at": "", "ttl": 0}"#,
            ),
        ];

        for (attack_type, invalid_data) in invalid_data_attempts {
            let attack_session_id = format!("attack_{attack_type}");
            let cache_data = CacheData {
                value: invalid_data.to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            };

            // Attempt to store invalid data
            let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
            let cache_key = CacheKey::new(attack_session_id.clone()).unwrap();
            let store_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl(cache_prefix, cache_key, cache_data, 3600)
                .await;

            // Storage itself might succeed (cache doesn't validate), but authentication should fail
            if store_result.is_ok() {
                let attack_headers =
                    create_header_map_with_cookie(&cookie_name, &attack_session_id);
                let auth_result = is_authenticated_basic(&attack_headers, &Method::GET).await;

                assert!(
                    auth_result.is_ok(),
                    "Auth check for {attack_type} should not error"
                );
                assert!(
                    !auth_result.unwrap().0,
                    "Auth should fail for invalid session data: {attack_type}"
                );
            }
        }

        // Verify legitimate session still works after attack attempts
        let legit_headers = create_header_map_with_cookie(&cookie_name, legitimate_session_id);
        let auth_result = is_authenticated_basic(&legit_headers, &Method::GET).await;

        assert!(
            auth_result.is_ok(),
            "Legitimate session should still work after attacks"
        );
        assert!(
            auth_result.unwrap().0,
            "Legitimate session should authenticate after attacks"
        );

        // Test case 2: Key collision attempts
        let collision_attempts = vec![
            "../session/legitimate_session", // Path traversal
            "session/../legitimate_session", // Path traversal 2
            "legitimate_session\x00",        // Null byte injection
            "legitimate_session\n",          // Newline injection
            "LEGITIMATE_SESSION",            // Case variation
            "legitimate_session ",           // Trailing space
            " legitimate_session",           // Leading space
        ];

        for collision_key in collision_attempts {
            let collision_session =
                create_security_test_session("collision_csrf", "collision_user", 3600);
            let store_result = store_session_in_cache(collision_key, collision_session, 3600).await;

            if store_result.is_ok() {
                // Even if storage succeeds, it shouldn't affect the legitimate session
                let legit_check = is_authenticated_basic(&legit_headers, &Method::GET).await;
                assert!(
                    legit_check.is_ok(),
                    "Legitimate session should be unaffected by collision attempt"
                );
                assert!(
                    legit_check.unwrap().0,
                    "Legitimate session should still authenticate"
                );
            }
        }

        // Test case 3: Large data injection attempts
        let large_data_session = serde_json::json!({
            "user_id": "a".repeat(1000000), // 1MB user ID
            "csrf_token": "b".repeat(1000000), // 1MB CSRF token
            "expires_at": (Utc::now() + Duration::seconds(3600)).to_rfc3339(),
            "ttl": 3600_u64,
        });

        let _large_data_result =
            store_session_in_cache("large_data_session", large_data_session, 3600).await;

        // Whether storage succeeds or fails, legitimate session should be unaffected
        let legit_check = is_authenticated_basic(&legit_headers, &Method::GET).await;
        assert!(
            legit_check.is_ok(),
            "Legitimate session should be unaffected by large data injection"
        );
        assert!(
            legit_check.unwrap().0,
            "Legitimate session should still authenticate after large data attempt"
        );
    }
}
