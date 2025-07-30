use headers::Cookie;
use http::header::{HeaderMap, SET_COOKIE};

use chrono::{Duration, Utc};
use jsonwebtoken::Algorithm;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::oauth2::config::{
    OAUTH2_CSRF_COOKIE_MAX_AGE, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_GOOGLE_CLIENT_ID,
    OAUTH2_QUERY_STRING, OAUTH2_REDIRECT_URI, OAUTH2_RESPONSE_MODE, get_auth_url,
};
use crate::oauth2::errors::OAuth2Error;
use crate::oauth2::types::{AuthResponse, GoogleUserInfo, StateParams, StoredToken};
use crate::session::get_session_id_from_headers;
use crate::utils::base64url_encode;

use super::google::{exchange_code_for_token, fetch_user_data_from_google};
use super::idtoken::{IdInfo as GoogleIdInfo, verify_idtoken_with_algorithm};
use super::utils::{
    decode_state, encode_state, generate_store_token, get_token_from_store,
    remove_token_from_store, store_token_in_cache,
};

/// Prepares an OAuth2 authentication request URL and necessary headers.
///
/// This function generates a secure OAuth2 authorization URL for redirecting users
/// to the identity provider (e.g., Google). It also sets up CSRF protection by
/// generating and storing a state parameter.
///
/// # Arguments
///
/// * `headers` - HTTP headers from the client request, used to extract user agent and other info
/// * `mode` - Optional authentication mode (e.g., "login", "create_user", etc.)
///
/// # Returns
///
/// * `Ok((String, HeaderMap))` - The authorization URL and response headers
/// * `Err(OAuth2Error)` - If an error occurs during preparation
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::prepare_oauth2_auth_request;
/// use http::HeaderMap;
///
/// async fn start_oauth_flow(request_headers: HeaderMap) -> Result<(String, HeaderMap), Box<dyn std::error::Error>> {
///     let (auth_url, response_headers) = prepare_oauth2_auth_request(request_headers, Some("login")).await?;
///     Ok((auth_url, response_headers))
/// }
/// ```
pub async fn prepare_oauth2_auth_request(
    headers: HeaderMap,
    mode: Option<&str>,
) -> Result<(String, HeaderMap), OAuth2Error> {
    // Resolve configuration values
    let auth_base_url = get_auth_url().await?;
    let response_mode = OAUTH2_RESPONSE_MODE.as_str();

    // Delegate to the internal function that builds the request
    prepare_oauth2_auth_request_with_params(headers, mode, &auth_base_url, response_mode).await
}

/// Internal function that builds OAuth2 authorization request with provided parameters
///
/// This separation allows for comprehensive testing by injecting both auth URL and response mode,
/// enabling unit tests to validate cookie security attributes for all response modes.
async fn prepare_oauth2_auth_request_with_params(
    headers: HeaderMap,
    mode: Option<&str>,
    auth_base_url: &str,
    response_mode: &str,
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
        auth_base_url,
        OAUTH2_QUERY_STRING.as_str(),
        OAUTH2_GOOGLE_CLIENT_ID.as_str(),
        OAUTH2_REDIRECT_URI.as_str(),
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );

    tracing::debug!("Auth URL: {:#?}", auth_url);

    let mut response_headers = HeaderMap::new();

    // Set SameSite attribute based on response mode
    // form_post requires SameSite=None because it's a cross-site POST
    // query (redirect) can use SameSite=Lax for better security
    let samesite = match response_mode.to_lowercase().as_str() {
        "form_post" => "None",
        "query" => "Lax",
        _ => "Lax", // Default to Lax for unknown response modes
    };

    let cookie = format!(
        "{}={}; SameSite={}; Secure; HttpOnly; Path=/; Max-Age={}",
        *OAUTH2_CSRF_COOKIE_NAME, csrf_token, samesite, *OAUTH2_CSRF_COOKIE_MAX_AGE as i64
    );

    response_headers.append(
        SET_COOKIE,
        cookie
            .parse()
            .map_err(|_| OAuth2Error::Cookie("Failed to parse cookie".to_string()))?,
    );

    tracing::debug!("Headers: {:#?}", response_headers);

    Ok((auth_url, response_headers))
}

pub(crate) async fn get_idinfo_userinfo(
    auth_response: &AuthResponse,
) -> Result<(GoogleIdInfo, GoogleUserInfo), OAuth2Error> {
    let pkce_verifier = get_pkce_verifier(auth_response).await?;
    let (access_token, id_token) =
        exchange_code_for_token(auth_response.code.clone(), pkce_verifier).await?;

    let (idinfo, algorithm) =
        verify_idtoken_with_algorithm(id_token, OAUTH2_GOOGLE_CLIENT_ID.to_string())
            .await
            .map_err(|e| OAuth2Error::IdToken(e.to_string()))?;

    verify_at_hash(&idinfo, &access_token, algorithm)?;

    verify_nonce(auth_response, idinfo.clone()).await?;

    let userinfo = fetch_user_data_from_google(access_token).await?;

    if idinfo.sub != userinfo.sub {
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
    // Verify nonce matches between ID token and stored session
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

/// Calculate at_hash according to OpenID Connect specification
///
/// The at_hash is calculated by:
/// 1. Hashing the access token using the same algorithm as the ID token's JOSE header
/// 2. Taking the left-most half of the hash
/// 3. Base64url encoding the result
fn calculate_at_hash(access_token: &str, algorithm: Algorithm) -> Result<String, OAuth2Error> {
    fn half_hash<D: Digest>(data: &[u8]) -> Vec<u8> {
        let hash = D::digest(data);
        hash[..hash.len() / 2].to_vec() // Take left-most half
    }

    let hash_bytes = match algorithm {
        Algorithm::RS256 | Algorithm::HS256 | Algorithm::ES256 => {
            half_hash::<Sha256>(access_token.as_bytes())
        }
        Algorithm::RS384 | Algorithm::HS384 | Algorithm::ES384 => {
            half_hash::<Sha384>(access_token.as_bytes())
        }
        Algorithm::RS512 | Algorithm::HS512 => half_hash::<Sha512>(access_token.as_bytes()),
        _ => {
            return Err(OAuth2Error::UnsupportedAlgorithm(format!(
                "Unsupported algorithm for at_hash calculation: {algorithm:?}"
            )));
        }
    };

    Ok(base64url_encode(hash_bytes)?)
}

/// Verify at_hash according to OpenID Connect specification
///
/// This function verifies that the at_hash in the ID token matches the calculated
/// hash of the access token using the algorithm specified in the ID token's JOSE header.
///
/// # Arguments
///
/// * `idinfo` - The ID token information containing the at_hash claim
/// * `access_token` - The access token to verify against
/// * `algorithm` - The algorithm from the ID token's JOSE header
///
/// # Returns
///
/// * `Ok(())` - If verification succeeds or at_hash is not present
/// * `Err(OAuth2Error)` - If verification fails or calculation error occurs
fn verify_at_hash(
    idinfo: &GoogleIdInfo,
    access_token: &str,
    algorithm: Algorithm,
) -> Result<(), OAuth2Error> {
    if idinfo.at_hash.is_none() {
        tracing::warn!("at_hash is None in ID Token: {:#?}", idinfo);
        return Ok(());
    }

    // Calculate at_hash according to OpenID Connect specification:
    // 1. Hash the access token using the same algorithm as the ID token's JOSE header
    // 2. Take the left-most half of the hash (first 16 bytes for SHA256)
    // 3. Base64url encode the result
    let calculated_at_hash = calculate_at_hash(access_token, algorithm)?;

    tracing::debug!(
        "ID Token at_hash: {:?}, Access Token Hash: {:?}",
        idinfo.at_hash,
        calculated_at_hash
    );

    if idinfo.at_hash.as_ref().unwrap() != &calculated_at_hash {
        tracing::error!(
            "at_hash mismatch: ID Token at_hash: {:?}, Access Token Hash: {:?}",
            idinfo.at_hash,
            calculated_at_hash
        );
        return Err(OAuth2Error::AtHashMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_environment;
    use std::collections::HashMap;

    /// Test OAuth2 request preparation with an authenticated session
    ///
    /// This test verifies that OAuth2 authorization request generation works correctly
    /// when a user session exists, including proper state encoding and URL construction.
    ///
    #[tokio::test]
    async fn test_oauth2_request_preparation_with_session() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );
        headers.insert(
            http::header::COOKIE,
            http::HeaderValue::from_static("session_id=test_session_123"),
        );

        // Use the internal function with a test auth URL to avoid external dependencies
        let test_auth_url = "https://test.example.com/oauth/authorize";
        let current_response_mode = OAUTH2_RESPONSE_MODE.as_str();
        let result = prepare_oauth2_auth_request_with_params(
            headers,
            Some("signup"),
            test_auth_url,
            current_response_mode,
        )
        .await;

        assert!(result.is_ok());
        let (auth_url, response_headers) = result.unwrap();

        // Test the actual behavior, not implementation details
        let parsed_url = url::Url::parse(&auth_url).expect("Should generate valid URL");

        // Test that auth URL starts with our test URL
        assert!(
            auth_url.starts_with(test_auth_url),
            "Should use provided auth URL"
        );

        // Test OAuth2 parameters are present
        let params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
        assert!(params.contains_key("client_id"), "Should include client_id");
        assert!(
            params.contains_key("redirect_uri"),
            "Should include redirect_uri"
        );
        assert!(
            params.contains_key("state"),
            "Should include state parameter"
        );
        assert!(
            params.contains_key("nonce"),
            "Should include nonce for OIDC"
        );
        assert!(
            params.contains_key("code_challenge"),
            "Should include PKCE challenge"
        );
        assert_eq!(
            params.get("code_challenge_method"),
            Some(&"S256".to_string()),
            "Should use S256 PKCE method"
        );
        assert_eq!(
            params.get("response_type"),
            Some(&"code".to_string()),
            "Should use authorization code flow"
        );

        // Verify CSRF cookie is set in response headers
        let set_cookie_headers: Vec<_> = response_headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();

        assert!(!set_cookie_headers.is_empty());
        let csrf_cookie = set_cookie_headers
            .iter()
            .find(|cookie| cookie.contains(&*OAUTH2_CSRF_COOKIE_NAME))
            .expect("CSRF cookie should be set");

        // Debug: print the actual cookie to see its format
        println!("Actual cookie: {csrf_cookie}");

        assert!(csrf_cookie.contains("HttpOnly"));

        // Verify SameSite attribute matches the response mode
        // form_post mode should use SameSite=None, query mode should use SameSite=Lax
        let expected_samesite = match OAUTH2_RESPONSE_MODE.to_lowercase().as_str() {
            "form_post" => "SameSite=None",
            "query" => "SameSite=Lax",
            _ => "SameSite=Lax", // Default fallback
        };
        assert!(
            csrf_cookie.contains(expected_samesite),
            "Expected {expected_samesite} in cookie: {csrf_cookie}"
        );
    }

    /// Test OAuth2 request preparation without an authenticated session
    ///
    /// This test verifies that OAuth2 authorization request generation works correctly
    /// when no user session exists, handling the anonymous case.
    ///
    #[tokio::test]
    async fn test_oauth2_request_preparation_without_session() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Use the internal function with a test auth URL to avoid external dependencies
        let test_auth_url = "https://test.example.com/oauth/authorize";
        let current_response_mode = OAUTH2_RESPONSE_MODE.as_str();
        let result = prepare_oauth2_auth_request_with_params(
            headers,
            None,
            test_auth_url,
            current_response_mode,
        )
        .await;

        assert!(result.is_ok());
        let (auth_url, response_headers) = result.unwrap();

        // Test the actual behavior, not implementation details
        let parsed_url = url::Url::parse(&auth_url).expect("Should generate valid URL");

        // Test that auth URL starts with our test URL
        assert!(
            auth_url.starts_with(test_auth_url),
            "Should use provided auth URL"
        );

        // Test OAuth2 parameters are present even without session
        let params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();
        assert!(params.contains_key("client_id"), "Should include client_id");
        assert!(
            params.contains_key("redirect_uri"),
            "Should include redirect_uri"
        );
        assert!(
            params.contains_key("state"),
            "Should include state parameter"
        );
        assert!(
            params.contains_key("nonce"),
            "Should include nonce for OIDC"
        );
        assert!(
            params.contains_key("code_challenge"),
            "Should include PKCE challenge"
        );
        assert_eq!(
            params.get("code_challenge_method"),
            Some(&"S256".to_string()),
            "Should use S256 PKCE method"
        );
        assert_eq!(
            params.get("response_type"),
            Some(&"code".to_string()),
            "Should use authorization code flow"
        );

        // Test that CSRF cookie is set even without session
        assert!(
            response_headers.contains_key("set-cookie"),
            "Should set CSRF cookie"
        );
    }

    /// Test state encoding and decoding roundtrip
    ///
    /// This test verifies that StateParams can be encoded to base64 and decoded back
    /// to the original values, ensuring the serialization roundtrip maintains data integrity.
    ///
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

    /// Test state decoding with invalid base64 input
    ///
    /// This test verifies that `decode_state` returns an appropriate error when given
    /// invalid base64 input that cannot be decoded.
    ///
    #[tokio::test]
    async fn test_state_decoding_invalid_base64() {
        let invalid_state = "invalid_base64_@#$%";
        let result = decode_state(invalid_state);

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::DecodeState(_)) => {}
            Ok(_) => {
                unreachable!("Unexpectedly got Ok");
            }
            Err(err) => {
                unreachable!("Expected DecodeState error, got {:?}", err);
            }
        }
    }

    /// Test state decoding with invalid JSON payload
    ///
    /// This test verifies that `decode_state` returns an appropriate error when given
    /// valid base64 that contains invalid JSON that cannot be parsed.
    ///
    #[tokio::test]
    async fn test_state_decoding_invalid_json() {
        // Create invalid JSON by encoding invalid data
        let invalid_json = base64url_encode(b"not valid json".to_vec()).unwrap();
        let result = decode_state(&invalid_json);

        assert!(result.is_err());
        match result {
            Err(OAuth2Error::Serde(_)) => {}
            Ok(_) => {
                unreachable!("Unexpectedly got Ok");
            }
            Err(err) => {
                unreachable!("Expected Serde error, got {:?}", err);
            }
        }
    }

    /// Test CSRF cookie SameSite attribute for form_post response mode
    ///
    /// This test verifies that form_post mode uses SameSite=None to allow cross-origin POST requests.
    ///
    #[tokio::test]
    async fn test_oauth2_csrf_cookie_samesite_form_post_mode() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        let test_auth_url = "https://test.example.com/oauth/authorize";
        let result =
            prepare_oauth2_auth_request_with_params(headers, None, test_auth_url, "form_post")
                .await;

        assert!(result.is_ok());
        let (_, response_headers) = result.unwrap();

        let csrf_cookie = extract_csrf_cookie(&response_headers);

        // Verify security attributes
        assert!(
            csrf_cookie.contains("HttpOnly"),
            "Cookie should be HttpOnly"
        );
        assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
        assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

        // Verify SameSite=None for form_post mode
        assert!(
            csrf_cookie.contains("SameSite=None"),
            "form_post mode should use SameSite=None for cross-origin POST requests. Cookie: {csrf_cookie}"
        );
    }

    /// Test CSRF cookie SameSite attribute for query response mode
    ///
    /// This test verifies that query mode uses SameSite=Lax for redirect-based flows.
    ///
    #[tokio::test]
    async fn test_oauth2_csrf_cookie_samesite_query_mode() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        let test_auth_url = "https://test.example.com/oauth/authorize";
        let result =
            prepare_oauth2_auth_request_with_params(headers, None, test_auth_url, "query").await;

        assert!(result.is_ok());
        let (_, response_headers) = result.unwrap();

        let csrf_cookie = extract_csrf_cookie(&response_headers);

        // Verify security attributes
        assert!(
            csrf_cookie.contains("HttpOnly"),
            "Cookie should be HttpOnly"
        );
        assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
        assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

        // Verify SameSite=Lax for query mode
        assert!(
            csrf_cookie.contains("SameSite=Lax"),
            "query mode should use SameSite=Lax for redirect-based flows. Cookie: {csrf_cookie}"
        );
    }

    /// Test CSRF cookie SameSite attribute for unknown response mode
    ///
    /// This test verifies that unknown response modes default to SameSite=Lax for security.
    ///
    #[tokio::test]
    async fn test_oauth2_csrf_cookie_samesite_unknown_mode() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        let test_auth_url = "https://test.example.com/oauth/authorize";
        let result =
            prepare_oauth2_auth_request_with_params(headers, None, test_auth_url, "unknown_mode")
                .await;

        assert!(result.is_ok());
        let (_, response_headers) = result.unwrap();

        let csrf_cookie = extract_csrf_cookie(&response_headers);

        // Verify security attributes
        assert!(
            csrf_cookie.contains("HttpOnly"),
            "Cookie should be HttpOnly"
        );
        assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
        assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

        // Verify SameSite=Lax as default for unknown modes
        assert!(
            csrf_cookie.contains("SameSite=Lax"),
            "Unknown response mode should default to SameSite=Lax. Cookie: {csrf_cookie}"
        );
    }

    /// Test CSRF cookie SameSite attribute configuration based on current config
    ///
    /// This integration test verifies that CSRF cookies are configured with appropriate SameSite
    /// attributes based on the actual OAuth2 response mode configuration.
    ///
    #[tokio::test]
    async fn test_oauth2_csrf_cookie_samesite_based_on_response_mode() {
        init_test_environment().await;

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            http::HeaderValue::from_static("test-user-agent"),
        );

        // Use the internal function with a test auth URL to avoid external dependencies
        let test_auth_url = "https://test.example.com/oauth/authorize";
        let current_response_mode = OAUTH2_RESPONSE_MODE.as_str();
        let result = prepare_oauth2_auth_request_with_params(
            headers,
            None,
            test_auth_url,
            current_response_mode,
        )
        .await;

        assert!(result.is_ok());
        let (_, response_headers) = result.unwrap();

        let csrf_cookie = extract_csrf_cookie(&response_headers);

        // Verify the cookie has required security attributes
        assert!(
            csrf_cookie.contains("HttpOnly"),
            "Cookie should be HttpOnly"
        );
        assert!(csrf_cookie.contains("Secure"), "Cookie should be Secure");
        assert!(csrf_cookie.contains("Path=/"), "Cookie should have Path=/");

        // Verify SameSite attribute matches the configured response mode
        let current_mode = OAUTH2_RESPONSE_MODE.to_lowercase();
        match current_mode.as_str() {
            "form_post" => {
                assert!(
                    csrf_cookie.contains("SameSite=None"),
                    "form_post mode should use SameSite=None for cross-origin POST requests. Cookie: {csrf_cookie}"
                );
            }
            "query" => {
                assert!(
                    csrf_cookie.contains("SameSite=Lax"),
                    "query mode should use SameSite=Lax for redirect-based flows. Cookie: {csrf_cookie}"
                );
            }
            _ => {
                assert!(
                    csrf_cookie.contains("SameSite=Lax"),
                    "Unknown response mode should default to SameSite=Lax. Cookie: {csrf_cookie}"
                );
            }
        }
    }

    /// Helper function to extract CSRF cookie from response headers
    fn extract_csrf_cookie(response_headers: &HeaderMap) -> String {
        let set_cookie_headers: Vec<_> = response_headers
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();

        assert!(
            !set_cookie_headers.is_empty(),
            "Should have set-cookie headers"
        );

        set_cookie_headers
            .iter()
            .find(|cookie| cookie.contains(&*OAUTH2_CSRF_COOKIE_NAME))
            .expect("CSRF cookie should be set")
            .to_string()
    }
}
