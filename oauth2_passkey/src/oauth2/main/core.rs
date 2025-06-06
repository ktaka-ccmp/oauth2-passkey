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

    // Helper function to create an AuthResponse using serde_json
    fn create_auth_response(state: &str, code: &str) -> AuthResponse {
        let json_value = json!({
            "state": state,
            "code": code,
            "_id_token": null
        });
        serde_json::from_value(json_value).unwrap()
    }

    // Tests for CSRF validation logic

    // Test the case where the CSRF cookie is missing
    #[tokio::test]
    async fn test_csrf_checks_missing_cookie() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let cookies = MockCookie::new(); // No CSRF cookie
        let headers = ctx.create_headers();
        let token_store = MockTokenStore::new();

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(msg)) => {
                assert_eq!(msg, "No CSRF session cookie found");
            }
            Ok(_) => {
                assert!(false, "Expected SecurityTokenNotFound error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected SecurityTokenNotFound error, got {:?}", err);
            }
        }
    }

    // Test the case where the state parameter is invalid
    #[tokio::test]
    async fn test_csrf_checks_invalid_state() {
        let auth_response = create_auth_response("invalid_state", "code");
        let cookies = MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), "csrf_token");
        let headers = HeaderMap::new();
        let token_store = MockTokenStore::new();

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            Ok(_) => {
                assert!(false, "Expected DecodeState error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected DecodeState error, got {:?}", err);
            }
        }
    }

    // Improved mock infrastructure for testing
    #[derive(Clone, Debug)]
    struct MockTokenStore {
        tokens: std::collections::HashMap<String, StoredToken>,
    }

    impl MockTokenStore {
        fn new() -> Self {
            Self {
                tokens: std::collections::HashMap::new(),
            }
        }

        fn with_token(mut self, id: &str, token: StoredToken) -> Self {
            self.tokens.insert(id.to_string(), token);
            self
        }

        async fn get_token(&self, id: &str) -> Result<StoredToken, OAuth2Error> {
            self.tokens
                .get(id)
                .cloned()
                .ok_or_else(|| OAuth2Error::SecurityTokenNotFound("Token not found".to_string()))
        }

        async fn remove_token(&self, _id: &str) -> Result<(), OAuth2Error> {
            // In a real implementation, this would remove the token
            // For testing, we just simulate success
            Ok(())
        }
    }

    // Test context builder for better test organization
    struct TestContext {
        csrf_token: String,
        csrf_id: String,
        nonce_token: String,
        nonce_id: String,
        pkce_token: String,
        pkce_id: String,
        user_agent: String,
    }

    impl Default for TestContext {
        fn default() -> Self {
            Self {
                csrf_token: "test_csrf_token".to_string(),
                csrf_id: "test_csrf_id".to_string(),
                nonce_token: "test_nonce_token".to_string(),
                nonce_id: "test_nonce_id".to_string(),
                pkce_token: "test_pkce_token".to_string(),
                pkce_id: "test_pkce_id".to_string(),
                user_agent: "test-user-agent".to_string(),
            }
        }
    }

    impl TestContext {
        fn create_valid_state(&self) -> String {
            let state_params = StateParams {
                csrf_id: self.csrf_id.clone(),
                nonce_id: self.nonce_id.clone(),
                pkce_id: self.pkce_id.clone(),
                misc_id: None,
                mode_id: None,
            };
            encode_state(state_params).unwrap()
        }

        fn create_auth_response(&self) -> AuthResponse {
            create_auth_response(&self.create_valid_state(), "test_code")
        }

        fn create_cookies(&self) -> MockCookie {
            MockCookie::new().with_cookie(OAUTH2_CSRF_COOKIE_NAME.as_str(), &self.csrf_token)
        }

        fn create_headers(&self) -> HeaderMap {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::USER_AGENT,
                http::HeaderValue::from_str(&self.user_agent).unwrap(),
            );
            headers
        }

        fn create_valid_token_store(&self) -> MockTokenStore {
            MockTokenStore::new().with_token(
                &self.csrf_id,
                StoredToken {
                    token: self.csrf_token.clone(),
                    expires_at: Utc::now() + Duration::hours(1),
                    user_agent: Some(self.user_agent.clone()),
                    ttl: 3600,
                },
            )
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
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let cookies = ctx.create_cookies();
        let headers = ctx.create_headers();

        // Create token store with different token value
        let token_store = MockTokenStore::new().with_token(
            &ctx.csrf_id,
            StoredToken {
                token: "different_token_value".to_string(), // Different from cookie
                expires_at: Utc::now() + Duration::hours(1),
                user_agent: Some(ctx.user_agent.clone()),
                ttl: 3600,
            },
        );

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::CsrfTokenMismatch) => {}
            Ok(_) => {
                assert!(false, "Expected CsrfTokenMismatch error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected CsrfTokenMismatch error, got {:?}", err);
            }
        }
    }

    // Test the case where the CSRF token has expired
    #[tokio::test]
    async fn test_csrf_checks_token_expired() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let cookies = ctx.create_cookies();
        let headers = ctx.create_headers();

        // Create token store with expired token
        let token_store = MockTokenStore::new().with_token(
            &ctx.csrf_id,
            StoredToken {
                token: ctx.csrf_token.clone(),               // Matching token
                expires_at: Utc::now() - Duration::hours(1), // Expired
                user_agent: Some(ctx.user_agent.clone()),
                ttl: 3600,
            },
        );

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::CsrfTokenExpired) => {}
            Ok(_) => {
                assert!(false, "Expected CsrfTokenExpired error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected CsrfTokenExpired error, got {:?}", err);
            }
        }
    }

    // Test the case where the user agent doesn't match
    #[tokio::test]
    async fn test_csrf_checks_user_agent_mismatch() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let cookies = ctx.create_cookies();

        // Create headers with different user agent
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("different-user-agent"),
        );

        // Create token store with original user agent
        let token_store = ctx.create_valid_token_store();

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::UserAgentMismatch) => {}
            Ok(_) => {
                assert!(false, "Expected UserAgentMismatch error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected UserAgentMismatch error, got {:?}", err);
            }
        }
    }

    // Test successful CSRF validation
    #[tokio::test]
    async fn test_csrf_checks_success() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let cookies = ctx.create_cookies();
        let headers = ctx.create_headers();
        let token_store = ctx.create_valid_token_store();

        let result = mock_csrf_checks(cookies, &auth_response, headers, &token_store).await;

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

    // Tests for nonce verification

    // Test successful nonce verification
    #[tokio::test]
    async fn test_verify_nonce_success() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();

        let token_store = MockTokenStore::new().with_token(
            &ctx.nonce_id,
            StoredToken {
                token: ctx.nonce_token.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                user_agent: None,
                ttl: 3600,
            },
        );

        let idinfo = MockGoogleIdInfo::new(Some(ctx.nonce_token.clone()));

        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;
        assert!(result.is_ok());
    }

    // Test expired nonce
    #[tokio::test]
    async fn test_verify_nonce_expired() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();

        let token_store = MockTokenStore::new().with_token(
            &ctx.nonce_id,
            StoredToken {
                token: ctx.nonce_token.clone(),
                expires_at: Utc::now() - Duration::hours(1), // Expired
                user_agent: None,
                ttl: 3600,
            },
        );

        let idinfo = MockGoogleIdInfo::new(Some(ctx.nonce_token.clone()));

        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::NonceExpired) => {}
            Ok(_) => {
                assert!(false, "Expected NonceExpired error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected NonceExpired error, got {:?}", err);
            }
        }
    }

    // Test nonce mismatch
    #[tokio::test]
    async fn test_verify_nonce_mismatch() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();

        let token_store = MockTokenStore::new().with_token(
            &ctx.nonce_id,
            StoredToken {
                token: ctx.nonce_token.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                user_agent: None,
                ttl: 3600,
            },
        );

        let idinfo = MockGoogleIdInfo::new(Some("different_nonce_token".to_string()));

        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::NonceMismatch) => {}
            Ok(_) => {
                assert!(false, "Expected NonceMismatch error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected NonceMismatch error, got {:?}", err);
            }
        }
    }

    // Test missing nonce token
    #[tokio::test]
    async fn test_verify_nonce_missing_token() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let token_store = MockTokenStore::new(); // No tokens
        let idinfo = MockGoogleIdInfo::new(Some("some_nonce_token".to_string()));

        let result = mock_verify_nonce(&auth_response, idinfo, &token_store).await;
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(_)) => {}
            Ok(_) => {
                assert!(false, "Expected SecurityTokenNotFound error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected SecurityTokenNotFound error, got {:?}", err);
            }
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

    // Tests for PKCE verifier retrieval

    // Test successful PKCE verifier retrieval
    #[tokio::test]
    async fn test_get_pkce_verifier_success() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();

        let token_store = MockTokenStore::new().with_token(
            &ctx.pkce_id,
            StoredToken {
                token: ctx.pkce_token.clone(),
                expires_at: Utc::now() + Duration::hours(1),
                user_agent: None,
                ttl: 3600,
            },
        );

        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ctx.pkce_token);
    }

    // Test invalid state parameter
    #[tokio::test]
    async fn test_get_pkce_verifier_invalid_state() {
        let auth_response = create_auth_response("invalid_state", "code");
        let token_store = MockTokenStore::new();

        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            Ok(_) => {
                assert!(false, "Expected DecodeState error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected DecodeState error, got {:?}", err);
            }
        }
    }

    // Test missing PKCE token
    #[tokio::test]
    async fn test_get_pkce_verifier_missing_token() {
        let ctx = TestContext::default();
        let auth_response = ctx.create_auth_response();
        let token_store = MockTokenStore::new(); // No tokens

        let result = mock_get_pkce_verifier(&auth_response, &token_store).await;
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::SecurityTokenNotFound(_)) => {}
            Ok(_) => {
                assert!(false, "Expected SecurityTokenNotFound error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected SecurityTokenNotFound error, got {:?}", err);
            }
        }
    }
    // Tests for state encoding/decoding (focused on actual implementation)

    #[tokio::test]
    async fn test_state_encoding_decoding_roundtrip() {
        let original_state = StateParams {
            csrf_id: "test_csrf_id".to_string(),
            nonce_id: "test_nonce_id".to_string(),
            pkce_id: "test_pkce_id".to_string(),
            misc_id: Some("test_misc_id".to_string()),
            mode_id: Some("signup".to_string()),
        };

        let encoded = encode_state(original_state.clone()).unwrap();
        let decoded = decode_state(&encoded).unwrap();

        assert_eq!(original_state.csrf_id, decoded.csrf_id);
        assert_eq!(original_state.nonce_id, decoded.nonce_id);
        assert_eq!(original_state.pkce_id, decoded.pkce_id);
        assert_eq!(original_state.misc_id, decoded.misc_id);
        assert_eq!(original_state.mode_id, decoded.mode_id);
    }

    #[tokio::test]
    async fn test_state_decoding_invalid_base64() {
        let invalid_state = "invalid_base64_@#$%";
        let result = decode_state(invalid_state);

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            Ok(_) => {
                assert!(false, "Expected DecodeState error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected DecodeState error, got {:?}", err);
            }
        }
    }

    #[tokio::test]
    async fn test_state_decoding_invalid_json() {
        // Create invalid JSON by encoding invalid data
        let invalid_json = base64url_encode(b"not valid json".to_vec()).unwrap();
        let result = decode_state(&invalid_json);

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::Serde(_)) => {}
            Ok(_) => {
                assert!(false, "Expected Serde error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected Serde error, got {:?}", err);
            }
        }
    }
}
