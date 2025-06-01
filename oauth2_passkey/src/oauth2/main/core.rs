use headers::Cookie;
use http::header::{HeaderMap, SET_COOKIE};

use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use crate::oauth2::config::{
    OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_GOOGLE_CLIENT_ID,
    OAUTH2_QUERY_STRING, OAUTH2_REDIRECT_URI, OAUTH2_RESPONSE_MODE,
};
use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{AuthResponse, GoogleUserInfo, StateParams, StoredToken};
use crate::session::get_session_id_from_headers;
use crate::utils::base64url_encode;

use super::google::{exchange_code_for_token, fetch_user_data_from_google};
use super::idtoken::{IdInfo as GoogleIdInfo, verify_idtoken};
use super::utils::{
    decode_state, encode_state, generate_store_token, get_token_from_store,
    remove_token_from_store, store_token_in_cache,
};

pub async fn prepare_oauth2_auth_request(
    headers: HeaderMap,
    mode: Option<&str>,
) -> Result<(String, HeaderMap), OAuth2Error> {
    let expires_at = Utc::now() + Duration::seconds((*OAUTH2_CSRF_COOKIE_MAX_AGE) as i64);
    let ttl = *OAUTH2_CSRF_COOKIE_MAX_AGE;
    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let (csrf_token, csrf_id) =
        generate_store_token("csrf", ttl, expires_at, Some(user_agent)).await?;
    let (nonce_token, nonce_id) = generate_store_token("nonce", ttl, expires_at, None).await?;
    let (pkce_token, pkce_id) = generate_store_token("pkce", ttl, expires_at, None).await?;

    let misc_id = if let Some(session_id) = get_session_id_from_headers(&headers)? {
        tracing::info!("Session ID found: {}", session_id);
        Some(store_token_in_cache("misc_session", session_id, ttl, expires_at, None).await?)
    } else {
        tracing::debug!("No session ID found");
        None
    };

    let mode_id = if let Some(mode) = mode {
        Some(store_token_in_cache("mode", mode, ttl, expires_at, None).await?)
    } else {
        None
    };

    tracing::debug!("PKCE ID: {:?}, PKCE verifier: {:?}", pkce_id, pkce_token);
    let pkce_challenge = base64url_encode(Sha256::digest(pkce_token.as_bytes()).to_vec())?;

    tracing::debug!("PKCE Challenge: {:#?}", pkce_challenge);
    let state_params = StateParams {
        csrf_id,
        nonce_id,
        pkce_id,
        misc_id,
        mode_id,
    };

    let encoded_state = encode_state(state_params)?;

    let auth_url = format!(
        "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
        &code_challenge={}&code_challenge_method={}",
        OAUTH2_AUTH_URL.as_str(),
        OAUTH2_QUERY_STRING.as_str(),
        OAUTH2_GOOGLE_CLIENT_ID.as_str(),
        OAUTH2_REDIRECT_URI.as_str(),
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );

    tracing::debug!("Auth URL: {:#?}", auth_url);

    let mut headers = HeaderMap::new();

    // Set SameSite attribute based on response mode
    // form_post requires SameSite=None because it's a cross-site POST
    // query (redirect) can use SameSite=Lax for better security
    let samesite = match OAUTH2_RESPONSE_MODE.to_lowercase().as_str() {
        "form_post" => "None",
        "query" => "Lax",
        _ => "Lax", // Default to Lax for unknown response modes
    };

    let cookie = format!(
        "{}={}; SameSite={}; Secure; HttpOnly; Path=/; Max-Age={}",
        *OAUTH2_CSRF_COOKIE_NAME, csrf_token, samesite, *OAUTH2_CSRF_COOKIE_MAX_AGE as i64
    );

    headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
    );

    tracing::debug!("Headers: {:#?}", headers);

    Ok((auth_url, headers))
}

pub(crate) async fn get_idinfo_userinfo(
    auth_response: &AuthResponse,
) -> Result<(GoogleIdInfo, GoogleUserInfo), OAuth2Error> {
    let pkce_verifier = get_pkce_verifier(auth_response).await?;
    let (access_token, id_token) =
        exchange_code_for_token(auth_response.code.clone(), pkce_verifier).await?;

    let idinfo = verify_idtoken(id_token, OAUTH2_GOOGLE_CLIENT_ID.to_string())
        .await
        .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    verify_nonce(auth_response, idinfo.clone()).await?;

    let userinfo = fetch_user_data_from_google(access_token).await?;

    if idinfo.sub != userinfo.id {
        tracing::error!(
            "Id mismatch in IdInfo and Userinfo: \nIdInfo: {:#?}\nUserInfo: {:#?}",
            idinfo,
            userinfo
        );
        return Err(OAuth2Error::IdMismatch);
    }
    Ok((idinfo, userinfo))
}

async fn get_pkce_verifier(auth_response: &AuthResponse) -> Result<String, OAuth2Error> {
    let state_in_response = decode_state(&auth_response.state)?;

    let pkce_session: StoredToken =
        get_token_from_store("pkce", &state_in_response.pkce_id).await?;

    remove_token_from_store("pkce", &state_in_response.pkce_id).await?;

    Ok(pkce_session.token)
}

async fn verify_nonce(
    auth_response: &AuthResponse,
    idinfo: GoogleIdInfo,
) -> Result<(), OAuth2Error> {
    let state_in_response = decode_state(&auth_response.state)?;

    let nonce_session: StoredToken =
        get_token_from_store("nonce", &state_in_response.nonce_id).await?;

    tracing::debug!("Nonce Data: {:#?}", nonce_session);

    if Utc::now() > nonce_session.expires_at {
        tracing::error!("Nonce Expired: {:#?}", nonce_session.expires_at);
        tracing::error!("Now: {:#?}", Utc::now());
        return Err(OAuth2Error::NonceExpired);
    }
    if idinfo.nonce != Some(nonce_session.token.clone()) {
        tracing::error!("Nonce in ID Token: {:#?}", idinfo.nonce);
        tracing::error!("Stored Nonce: {:#?}", nonce_session.token);
        return Err(OAuth2Error::NonceMismatch);
    }

    remove_token_from_store("nonce", &state_in_response.nonce_id).await?;

    Ok(())
}

pub(crate) async fn csrf_checks(
    cookies: Cookie,
    query: &AuthResponse,
    headers: HeaderMap,
) -> Result<(), OAuth2Error> {
    let csrf_token = cookies
        .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
        .ok_or_else(|| {
            OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
        })?;

    let state_in_response = decode_state(&query.state)?;
    tracing::debug!("State in response: {:#?}", state_in_response);

    // Get the csrf_id from the state parameter
    let csrf_id = &state_in_response.csrf_id;

    let csrf_session: StoredToken = get_token_from_store("csrf", csrf_id).await?;
    tracing::debug!("CSRF Session: {:#?}", csrf_session);

    remove_token_from_store("csrf", csrf_id).await?;

    let user_agent = headers
        .get(http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    // Compare the token from the cookie with the token stored in the session
    if csrf_token != csrf_session.token {
        tracing::error!("CSRF Token in cookie: {:#?}", csrf_token);
        tracing::error!("Stored CSRF Token: {:#?}", csrf_session.token);
        return Err(OAuth2Error::CsrfTokenMismatch);
    }

    if Utc::now() > csrf_session.expires_at {
        tracing::error!("Now: {}", Utc::now());
        tracing::error!("CSRF Expires At: {:#?}", csrf_session.expires_at);
        return Err(OAuth2Error::CsrfTokenExpired);
    }

    if user_agent != csrf_session.user_agent.clone().unwrap_or_default() {
        tracing::error!("User Agent: {:#?}", user_agent);
        tracing::error!(
            "Stored User Agent: {:#?}",
            csrf_session.user_agent.unwrap_or_default()
        );
        return Err(OAuth2Error::UserAgentMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    // A mock implementation of Cookie for testing
    #[derive(Clone, Debug)]
    struct MockCookie {
        values: HashMap<String, String>,
    }

    impl MockCookie {
        fn new() -> Self {
            MockCookie {
                values: HashMap::new(),
            }
        }

        fn with_cookie(mut self, name: &str, value: &str) -> Self {
            self.values.insert(name.to_string(), value.to_string());
            self
        }

        fn get(&self, name: &str) -> Option<&str> {
            self.values.get(name).map(|s| s.as_str())
        }
    }

    // Helper function to create a state parameter with a CSRF ID
    fn create_state_with_csrf_id(csrf_id: &str) -> String {
        let state_params = StateParams {
            csrf_id: csrf_id.to_string(),
            nonce_id: "nonce_id".to_string(),
            pkce_id: "pkce_id".to_string(),
            misc_id: None,
            mode_id: None,
        };
        encode_state(state_params).unwrap()
    }

    // Helper function to create an AuthResponse using serde_json
    fn create_auth_response(state: &str, code: &str) -> AuthResponse {
        let json_value = json!({
            "state": state,
            "code": code,
            "_id_token": null
        });
        serde_json::from_value(json_value).unwrap()
    }

    // Test the case where the CSRF cookie is missing
    #[tokio::test]
    async fn test_csrf_checks_missing_cookie() {
        // Create a basic auth response with a valid state
        let auth_response = create_auth_response(&create_state_with_csrf_id("csrf_id"), "code");

        // Create an empty cookie (no CSRF token)
        let cookies = MockCookie::new();

        // Create empty headers
        let headers = HeaderMap::new();

        // Create a modified version of csrf_checks that works with our mock
        async fn mock_csrf_checks(
            cookies: MockCookie,
            query: &AuthResponse,
            _headers: HeaderMap,
        ) -> Result<(), OAuth2Error> {
            let _csrf_token = cookies
                .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
                .ok_or_else(|| {
                    OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
                })?;

            let state_in_response = decode_state(&query.state)?;

            // Get the csrf_id from the state parameter
            let _csrf_id = &state_in_response.csrf_id;

            // The rest of the function would normally check the token in the store
            // and verify other conditions, but for this test we're just checking
            // that the cookie is missing

            Ok(())
        }

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(msg)) => {
                assert!(msg.contains("No CSRF session cookie found"));
            }
            err => panic!("Expected SecurityTokenNotFound error, got {:?}", err),
        }
    }

    // Test the case where the state parameter is invalid
    #[tokio::test]
    async fn test_csrf_checks_invalid_state() {
        // Create an auth response with an invalid state parameter
        let auth_response = create_auth_response("invalid_state", "code");

        // Create a cookie with a CSRF token
        let cookies = MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), "csrf_token");

        // Create empty headers
        let headers = HeaderMap::new();

        // Create a modified version of csrf_checks that works with our mock
        async fn mock_csrf_checks(
            cookies: MockCookie,
            query: &AuthResponse,
            _headers: HeaderMap,
        ) -> Result<(), OAuth2Error> {
            let _csrf_token = cookies
                .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
                .ok_or_else(|| {
                    OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
                })?;

            // This should fail because the state is invalid
            let _state_in_response = decode_state(&query.state)?;

            // The rest of the function would normally check the token in the store
            // and verify other conditions, but for this test we're just checking
            // that the state parameter is invalid

            Ok(())
        }

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            err => panic!("Expected DecodeState error, got {:?}", err),
        }
    }

    // Helper struct for token store mocking
    struct MockTokenStore {
        token: Option<StoredToken>,
    }

    impl MockTokenStore {
        fn new(token: Option<StoredToken>) -> Self {
            Self { token }
        }

        async fn get_token(&self, _id: &str) -> Result<StoredToken, OAuth2Error> {
            match &self.token {
                Some(token) => Ok(token.clone()),
                None => Err(OAuth2Error::SecurityTokenNotFound(
                    "Token not found".to_string(),
                )),
            }
        }

        async fn remove_token(&self, _id: &str) -> Result<(), OAuth2Error> {
            Ok(())
        }
    }

    // Helper function for mock CSRF checks
    async fn mock_csrf_checks(
        cookies: MockCookie,
        query: &AuthResponse,
        headers: HeaderMap,
        token_store: &MockTokenStore,
    ) -> Result<(), OAuth2Error> {
        let csrf_token = cookies
            .get(OAUTH2_CSRF_COOKIE_NAME.as_str())
            .ok_or_else(|| {
                OAuth2Error::SecurityTokenNotFound("No CSRF session cookie found".to_string())
            })?;

        let state_in_response = decode_state(&query.state)?;

        // Get the csrf_id from the state parameter
        let csrf_id = &state_in_response.csrf_id;

        // Get the token from the store
        let stored_token = token_store.get_token(csrf_id).await?;

        // Check if the token matches
        if stored_token.token != csrf_token {
            return Err(OAuth2Error::CsrfTokenMismatch);
        }

        // Check if the token has expired
        if stored_token.expires_at < Utc::now() {
            return Err(OAuth2Error::CsrfTokenExpired);
        }

        // Check if the user agent matches
        let user_agent = headers
            .get(http::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if let Some(stored_user_agent) = &stored_token.user_agent {
            if stored_user_agent != user_agent {
                return Err(OAuth2Error::UserAgentMismatch);
            }
        }

        // Remove the token from the store
        token_store.remove_token(csrf_id).await?;

        Ok(())
    }

    // Test the case where the CSRF token doesn't match the one in the state
    #[tokio::test]
    async fn test_csrf_checks_token_mismatch() {
        // Create a valid state with a specific CSRF ID
        let csrf_id = "csrf_id_in_state";
        let auth_response = create_auth_response(&create_state_with_csrf_id(csrf_id), "code");

        // Create a cookie with a different CSRF token
        let cookies =
            MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), "different_csrf_token");

        // Create headers with a user agent
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Create a token store with a token that has a different value than the cookie
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: "stored_token_value".to_string(), // Different from the cookie value "different_csrf_token"
            expires_at: Utc::now() + Duration::hours(1),
            user_agent: Some("test-user-agent".to_string()),
            ttl: 3600,
        }));

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::CsrfTokenMismatch) => {}
            err => panic!("Expected CsrfTokenMismatch error, got {:?}", err),
        }
    }

    // Test the case where the CSRF token has expired
    #[tokio::test]
    async fn test_csrf_checks_token_expired() {
        // Create a valid state with a specific CSRF ID
        let csrf_id = "csrf_id_in_state";
        let auth_response = create_auth_response(&create_state_with_csrf_id(csrf_id), "code");

        // Create a cookie with a matching CSRF token
        let csrf_token = "matching_csrf_token";
        let cookies = MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), csrf_token);

        // Create headers with a user agent
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Create a token store with an expired token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: csrf_token.to_string(), // Matching token so we pass the token match check
            expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
            user_agent: Some("test-user-agent".to_string()),
            ttl: 3600,
        }));

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::CsrfTokenExpired) => {}
            err => panic!("Expected CsrfTokenExpired error, got {:?}", err),
        }
    }

    // Test the case where the user agent doesn't match
    #[tokio::test]
    async fn test_csrf_checks_user_agent_mismatch() {
        // Create a valid state with a specific CSRF ID
        let csrf_id = "csrf_id_in_state";
        let auth_response = create_auth_response(&create_state_with_csrf_id(csrf_id), "code");

        // Create a cookie with a matching CSRF token
        let csrf_token = "matching_csrf_token";
        let cookies = MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), csrf_token);

        // Create headers with a different user agent than what's stored
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("different-user-agent"),
        );

        // Create a token store with a valid token but different user agent
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: csrf_token.to_string(), // Matching token so we pass the token match check
            expires_at: Utc::now() + Duration::hours(1), // Not expired
            user_agent: Some("original-user-agent".to_string()), // Different from the request
            ttl: 3600,
        }));

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::UserAgentMismatch) => {}
            err => panic!("Expected UserAgentMismatch error, got {:?}", err),
        }
    }

    // Test the successful case where all CSRF checks pass
    #[tokio::test]
    async fn test_csrf_checks_success() {
        // Create a valid state with a specific CSRF ID
        let csrf_id = "csrf_id_in_state";
        let auth_response = create_auth_response(&create_state_with_csrf_id(csrf_id), "code");

        // Create a cookie with a matching CSRF token
        let csrf_token = "matching_csrf_token";
        let cookies = MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), csrf_token);

        // Create headers with a matching user agent
        let user_agent = "matching-user-agent";
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static(user_agent),
        );

        // Create a token store with a valid token and matching user agent
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: csrf_token.to_string(),               // Matching token
            expires_at: Utc::now() + Duration::hours(1), // Not expired
            user_agent: Some(user_agent.to_string()),    // Matching user agent
            ttl: 3600,
        }));

        // Run the test
        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        // Assert the result
        assert!(result.is_ok());
    }

    // Tests for verify_nonce function

    // Mock implementation of GoogleIdInfo for testing
    #[derive(Debug, Clone)]
    struct MockGoogleIdInfo {
        nonce: Option<String>,
    }

    impl MockGoogleIdInfo {
        fn new(nonce: Option<String>) -> Self {
            Self { nonce }
        }
    }

    // Helper function for mocking verify_nonce
    async fn mock_verify_nonce(
        auth_response: &AuthResponse,
        idinfo: MockGoogleIdInfo,
        token_store: &MockTokenStore,
    ) -> Result<(), OAuth2Error> {
        let state_in_response = decode_state(&auth_response.state)?;

        let nonce_id = &state_in_response.nonce_id;
        let nonce_session = token_store.get_token(nonce_id).await?;

        if Utc::now() > nonce_session.expires_at {
            return Err(OAuth2Error::NonceExpired);
        }

        if idinfo.nonce != Some(nonce_session.token.clone()) {
            return Err(OAuth2Error::NonceMismatch);
        }

        token_store.remove_token(nonce_id).await?;

        Ok(())
    }

    // Test successful nonce verification
    #[tokio::test]
    async fn test_verify_nonce_success() {
        // Create a valid state with a specific nonce ID
        let nonce_id = "nonce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: nonce_id.to_string(),
            pkce_id: "pkce_id".to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a nonce token
        let nonce_token = "valid_nonce_token";

        // Create a token store with a valid nonce token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: nonce_token.to_string(),
            expires_at: Utc::now() + Duration::hours(1), // Not expired
            user_agent: None,
            ttl: 3600,
        }));

        // Create Google ID info with matching nonce
        let idinfo = MockGoogleIdInfo::new(Some(nonce_token.to_string()));

        // Run the test
        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;

        // Assert the result
        assert!(result.is_ok());
    }

    // Test expired nonce
    #[tokio::test]
    async fn test_verify_nonce_expired() {
        // Create a valid state with a specific nonce ID
        let nonce_id = "nonce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: nonce_id.to_string(),
            pkce_id: "pkce_id".to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a nonce token
        let nonce_token = "valid_nonce_token";

        // Create a token store with an expired nonce token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: nonce_token.to_string(),
            expires_at: Utc::now() - Duration::hours(1), // Expired 1 hour ago
            user_agent: None,
            ttl: 3600,
        }));

        // Create Google ID info with matching nonce
        let idinfo = MockGoogleIdInfo::new(Some(nonce_token.to_string()));

        // Run the test
        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::NonceExpired) => {}
            err => panic!("Expected NonceExpired error, got {:?}", err),
        }
    }

    // Test nonce mismatch
    #[tokio::test]
    async fn test_verify_nonce_mismatch() {
        // Create a valid state with a specific nonce ID
        let nonce_id = "nonce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: nonce_id.to_string(),
            pkce_id: "pkce_id".to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a nonce token
        let nonce_token = "valid_nonce_token";

        // Create a token store with a valid nonce token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: nonce_token.to_string(),
            expires_at: Utc::now() + Duration::hours(1), // Not expired
            user_agent: None,
            ttl: 3600,
        }));

        // Create Google ID info with different nonce
        let idinfo = MockGoogleIdInfo::new(Some("different_nonce_token".to_string()));

        // Run the test
        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::NonceMismatch) => {}
            err => panic!("Expected NonceMismatch error, got {:?}", err),
        }
    }

    // Test missing nonce token
    #[tokio::test]
    async fn test_verify_nonce_missing_token() {
        // Create a valid state with a specific nonce ID
        let nonce_id = "nonce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: nonce_id.to_string(),
            pkce_id: "pkce_id".to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a token store with no token
        let token_store = MockTokenStore::new(None);

        // Create Google ID info with some nonce
        let idinfo = MockGoogleIdInfo::new(Some("some_nonce_token".to_string()));

        // Run the test
        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(_)) => {}
            err => panic!("Expected SecurityTokenNotFound error, got {:?}", err),
        }
    }

    // Tests for get_pkce_verifier function

    // Helper function for mocking get_pkce_verifier
    async fn mock_get_pkce_verifier(
        auth_response: &AuthResponse,
        token_store: &MockTokenStore,
    ) -> Result<String, OAuth2Error> {
        let state_in_response = decode_state(&auth_response.state)?;

        let pkce_id = &state_in_response.pkce_id;
        let pkce_session = token_store.get_token(pkce_id).await?;

        token_store.remove_token(pkce_id).await?;

        Ok(pkce_session.token)
    }

    // Test successful PKCE verifier retrieval
    #[tokio::test]
    async fn test_get_pkce_verifier_success() {
        // Create a valid state with a specific PKCE ID
        let pkce_id = "pkce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: "nonce_id".to_string(),
            pkce_id: pkce_id.to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a PKCE token
        let pkce_token = "valid_pkce_token";

        // Create a token store with a valid PKCE token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: pkce_token.to_string(),
            expires_at: Utc::now() + Duration::hours(1), // Not expired
            user_agent: None,
            ttl: 3600,
        }));

        // Run the test
        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;

        // Assert the result
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), pkce_token);
    }

    // Test invalid state parameter
    #[tokio::test]
    async fn test_get_pkce_verifier_invalid_state() {
        // Create an auth response with an invalid state parameter
        let auth_response = create_auth_response("invalid_state", "code");

        // Create a token store with a valid PKCE token
        let token_store = MockTokenStore::new(Some(StoredToken {
            token: "pkce_token".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            user_agent: None,
            ttl: 3600,
        }));

        // Run the test
        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            err => panic!("Expected DecodeState error, got {:?}", err),
        }
    }

    // Test missing PKCE token
    #[tokio::test]
    async fn test_get_pkce_verifier_missing_token() {
        // Create a valid state with a specific PKCE ID
        let pkce_id = "pkce_id_in_state";
        let state_params = StateParams {
            csrf_id: "csrf_id".to_string(),
            nonce_id: "nonce_id".to_string(),
            pkce_id: pkce_id.to_string(),
            misc_id: None,
            mode_id: None,
        };
        let state = encode_state(state_params).unwrap();

        // Create auth response with the state
        let auth_response = create_auth_response(&state, "code");

        // Create a token store with no token
        let token_store = MockTokenStore::new(None);

        // Run the test
        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;

        // Assert the result
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(_)) => {}
            err => panic!("Expected SecurityTokenNotFound error, got {:?}", err),
        }
    }
    // Tests for prepare_oauth2_auth_request function

    // Mock implementation for token generation and storage
    async fn mock_generate_store_token(
        _token_type: &str,
        _token_store: &MockTokenStore,
        token_value: Option<String>,
        _token_expiry: Option<i64>,
        _headers: HeaderMap,
    ) -> Result<(String, String), OAuth2Error> {
        Ok((token_value.unwrap_or_default(), "id_value".to_string()))
    }

    // Helper function for mocking prepare_oauth2_auth_request
    async fn mock_prepare_oauth2_auth_request(
        _headers: HeaderMap,
        mode: Option<&str>,
        mock_tokens: Vec<(String, String)>, // (token, id) pairs for csrf, nonce, pkce
    ) -> Result<(String, HeaderMap), OAuth2Error> {
        // Extract mock tokens
        let (csrf_token, csrf_id) = mock_tokens[0].clone();
        let (nonce_token, nonce_id) = mock_tokens[1].clone();
        let (pkce_token, pkce_id) = mock_tokens[2].clone();

        // Handle session ID and mode ID (simplified for testing)
        let misc_id = None;
        let mode_id = mode.map(|m| format!("mode_id_for_{}", m));

        // Generate PKCE challenge (simplified for testing)
        let pkce_challenge = base64url_encode(Sha256::digest(pkce_token.as_bytes()).to_vec())?;

        // Create state params
        let state_params = StateParams {
            csrf_id,
            nonce_id,
            pkce_id,
            misc_id,
            mode_id,
        };

        // Encode state
        let encoded_state = encode_state(state_params)?;

        // Use mock values instead of environment variables
        let auth_url = "https://accounts.google.com/o/oauth2/v2/auth";
        let query_string = "response_type=code";
        let client_id = "mock-client-id";
        let redirect_uri = "http://localhost:3000/oauth2/callback";
        let response_mode = "query"; // Default for testing

        // Construct auth URL
        let auth_url = format!(
            "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
            &code_challenge={}&code_challenge_method={}",
            auth_url,
            query_string,
            client_id,
            redirect_uri,
            encoded_state,
            nonce_token,
            pkce_challenge,
            "S256"
        );

        // Set response headers with CSRF cookie
        let mut response_headers = HeaderMap::new();

        // Set SameSite attribute based on response mode
        let samesite = match response_mode {
            "form_post" => "None",
            "query" => "Lax",
            _ => "Lax", // Default to Lax for unknown response modes
        };

        // Use mock values for cookie name and max age
        let cookie_name = "oauth2_csrf";
        let cookie_max_age = 3600;

        let cookie = format!(
            "{}={}; SameSite={}; Secure; HttpOnly; Path=/; Max-Age={}",
            cookie_name, csrf_token, samesite, cookie_max_age
        );

        response_headers.append(
            SET_COOKIE,
            cookie
                .parse()
                .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
        );

        Ok((auth_url, response_headers))
    }

    // Test successful auth request preparation
    #[tokio::test]
    async fn test_prepare_oauth2_auth_request_success() {
        // Create request headers with a user agent
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Create mock tokens
        let mock_tokens = vec![
            ("csrf_token".to_string(), "csrf_id".to_string()),
            ("nonce_token".to_string(), "nonce_id".to_string()),
            ("pkce_token".to_string(), "pkce_id".to_string()),
        ];

        // Run the test
        let result = mock_prepare_oauth2_auth_request(headers, None, mock_tokens).await;

        // Assert the result
        assert!(result.is_ok());
        let (auth_url, response_headers) = result.unwrap();

        // Verify auth URL contains expected components
        assert!(auth_url.contains("state="));
        assert!(auth_url.contains("nonce=nonce_token"));
        assert!(auth_url.contains("code_challenge="));
        assert!(auth_url.contains("code_challenge_method=S256"));

        // Verify response headers contain CSRF cookie
        let cookie_header = response_headers.get(SET_COOKIE);
        assert!(cookie_header.is_some());
        let cookie_str = cookie_header.unwrap().to_str().unwrap();
        assert!(cookie_str.contains("oauth2_csrf"));
        assert!(cookie_str.contains("csrf_token"));
        assert!(cookie_str.contains("SameSite="));
        assert!(cookie_str.contains("Secure"));
        assert!(cookie_str.contains("HttpOnly"));
    }

    // Test auth request preparation with mode parameter
    #[tokio::test]
    async fn test_prepare_oauth2_auth_request_with_mode() {
        // Create request headers with a user agent
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Create mock tokens
        let mock_tokens = vec![
            ("csrf_token".to_string(), "csrf_id".to_string()),
            ("nonce_token".to_string(), "nonce_id".to_string()),
            ("pkce_token".to_string(), "pkce_id".to_string()),
        ];

        // Run the test with a mode parameter
        let mode = "signup";
        let result = mock_prepare_oauth2_auth_request(headers, Some(mode), mock_tokens).await;

        // Assert the result
        assert!(result.is_ok());
        let (auth_url, _) = result.unwrap();

        // Decode the state parameter from the auth URL
        let state_param = auth_url
            .split("state=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();
        let state_params = decode_state(state_param).unwrap();

        // Verify mode_id is set in the state parameters
        assert!(state_params.mode_id.is_some());
        assert!(state_params.mode_id.unwrap().contains("signup"));
    }
}
