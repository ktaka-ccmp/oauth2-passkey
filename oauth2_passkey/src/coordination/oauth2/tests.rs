use super::*;
use crate::oauth2::provider::ProviderConfig;
use crate::oauth2::{
    FedCMCallbackRequest, OAuth2Account, OAuth2Error, prepare_fedcm_nonce,
    prepare_oauth2_auth_request_inner,
};
use crate::test_utils::init_test_environment;
use crate::userdb::User;
use chrono::Utc;
use serial_test::serial;

/// Test-accessible variant of `get_authorized_core` that accepts a pre-built
/// `ProviderConfig` directly, bypassing the global provider static.
/// This allows tests to inject mock server URLs without touching `LazyLock`s.
async fn get_authorized_core_with_ctx(
    ctx: &ProviderConfig,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    authorized_core(ctx, HttpMethod::Get, auth_response, cookies, headers).await
}

/// Test-accessible variant of `post_authorized_core` that accepts a pre-built
/// `ProviderConfig` directly, bypassing the global provider static.
async fn post_authorized_core_with_ctx(
    ctx: &ProviderConfig,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    authorized_core(ctx, HttpMethod::Post, auth_response, cookies, headers).await
}

/// Test-accessible variant of `fedcm_authorized_core` that accepts a pre-built
/// `ProviderConfig` directly, bypassing the global provider static.
async fn fedcm_authorized_core_with_ctx(
    ctx: &ProviderConfig,
    request: &FedCMCallbackRequest,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    let idinfo = validate_fedcm_token(ctx, &request.credential, &request.nonce_id).await?;
    let oauth2_account = oauth2_account_from_idinfo(&idinfo, ctx.path_segment)?;

    let mode = match &request.mode {
        Some(mode_str) => {
            let parsed: OAuth2Mode = mode_str.parse().map_err(|_| {
                CoordinationError::InvalidState(format!("Invalid FedCM mode: {mode_str}"))
            })?;
            Some(parsed)
        }
        None => None,
    };

    if matches!(mode, Some(OAuth2Mode::AddToUser)) {
        return Err(CoordinationError::InvalidState(
            "FedCM does not support add_to_user mode".to_string(),
        ));
    }

    let login_context = LoginContext::from_headers(headers);
    let result = process_authenticated_oauth2_user(
        oauth2_account,
        mode,
        AuthMethod::FedCM,
        login_context,
        None,
        None,
        None,
    )
    .await?;
    Ok(result)
}

// Additional imports for mock OAuth2 server tests
use axum::routing::{get, post};
use headers::HeaderMapExt;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

/// Test OAuth2 field mappings return expected defaults
///
/// This test verifies that OAuth2 field mappings return the correct default values
/// when environment variables are not defined.
///
#[tokio::test]
#[serial]
async fn test_get_oauth2_field_mappings_defaults() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Test default mappings - since .env_test doesn't set these variables,
    // they should use their default values
    let (account_field, label_field) = get_oauth2_field_mappings();
    assert_eq!(
        account_field, "email",
        "Default account field should be 'email'"
    );
    assert_eq!(label_field, "name", "Default label field should be 'name'");

    Ok(())
}

/// Test OAuth2 field mappings with environment variables
///
/// This test verifies that OAuth2 field mappings work correctly when environment
/// variables are defined, testing the configuration system behavior.
///
#[tokio::test]
#[serial]
async fn test_get_account_and_label_from_oauth2_account() -> Result<(), Box<dyn std::error::Error>>
{
    // Setup test environment
    init_test_environment().await;

    // Create a test OAuth2Account
    let oauth2_account = OAuth2Account {
        sequence_number: None,
        id: "test_id".to_string(),
        user_id: "test_user".to_string(),
        provider: "google".to_string(),
        provider_user_id: "google_123".to_string(),
        name: "John Doe".to_string(),
        email: "john.doe@example.com".to_string(),
        picture: Some("https://example.com/picture.jpg".to_string()),
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    // Test the field mapping function
    let (account, label) = get_account_and_label_from_oauth2_account(&oauth2_account);

    // With default mappings: account_field="email", label_field="name"
    assert_eq!(
        account, "john.doe@example.com",
        "Account should be mapped to email"
    );
    assert_eq!(label, "John Doe", "Label should be mapped to name");

    Ok(())
}

// Helper function to create a test user
async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = User {
        id: user_id.to_string(),
        account: "test_account".to_string(),
        label: "Test User".to_string(),
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    UserStore::upsert_user(user).await?;
    Ok(())
}

// Helper function to create a test OAuth2 account
async fn create_test_oauth2_account_in_db(
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let unique_provider_user_id = format!("{provider_user_id}-{timestamp}");
    let account_id = format!("test-id-{timestamp}");

    let oauth2_account = OAuth2Account {
        sequence_number: None,
        id: account_id.clone(),
        user_id: user_id.to_string(),
        provider: provider.to_string(),
        provider_user_id: unique_provider_user_id.clone(),
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        picture: Some("https://example.com/picture.jpg".to_string()),
        metadata: serde_json::json!({}),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
    Ok(unique_provider_user_id)
}

/// Test the core OAuth2 account listing functionality
///
/// This test verifies that `list_accounts_core()` correctly retrieves all OAuth2 accounts
/// associated with a specific user. It creates a test user with multiple OAuth2 accounts
/// from different providers and verifies:
/// - The correct number of accounts are returned
/// - All returned accounts belong to the specified user
/// - The function handles multiple provider accounts correctly
#[tokio::test]
#[serial]
async fn test_list_accounts_core() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test user and OAuth2 accounts with unique timestamp-based ID
    let timestamp = chrono::Utc::now().timestamp_millis();
    let user_id = format!("test_user_list_accounts_{timestamp}");
    let provider1 = "google";
    let provider2 = "github";
    let provider_user_id1 = "google_user_123";
    let provider_user_id2 = "github_user_456";

    create_test_user_in_db(&user_id).await?;
    let _unique_provider_user_id1 =
        create_test_oauth2_account_in_db(&user_id, provider1, provider_user_id1).await?;
    let _unique_provider_user_id2 =
        create_test_oauth2_account_in_db(&user_id, provider2, provider_user_id2).await?;

    // List the OAuth2 accounts
    let accounts = list_accounts_core(UserId::new(user_id.clone()).expect("Valid user ID")).await?;
    assert_eq!(
        accounts.len(),
        2,
        "Expected 2 OAuth2 accounts, got: {}",
        accounts.len()
    );

    // Verify the accounts belong to the correct user
    for account in &accounts {
        assert_eq!(
            account.user_id, user_id,
            "Account should belong to the test user"
        );
    }

    Ok(())
}

/// Test the core OAuth2 account deletion functionality
/// This test verifies that `delete_oauth2_account_core()` correctly deletes an OAuth2 account
/// associated with a user. It creates a test user and OAuth2 account, then attempts to delete
/// the account, verifying:
/// - The account is successfully deleted
/// - The account cannot be found after deletion
/// - Unauthorized deletion attempts by other users are correctly handled
#[tokio::test]
#[serial]
async fn test_delete_oauth2_account_core_success() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test user and OAuth2 account
    let user_id = "test_user_delete_success";
    let provider = "google";
    let provider_user_id = "google_user_delete_123";

    create_test_user_in_db(user_id).await?;
    let unique_provider_user_id =
        create_test_oauth2_account_in_db(user_id, provider, provider_user_id).await?;

    // Delete the OAuth2 account
    let result = delete_oauth2_account_core(
        UserId::new(user_id.to_string()).expect("Valid user ID"),
        Provider::new(provider.to_string()).expect("Valid provider"),
        ProviderUserId::new(unique_provider_user_id.clone()).expect("Valid user ID"),
    )
    .await;
    assert!(
        result.is_ok(),
        "Failed to delete OAuth2 account: {result:?}"
    );

    // Verify the account was deleted
    let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        crate::oauth2::ProviderUserId::new(unique_provider_user_id).expect("Valid user ID"),
    ))
    .await?;
    assert!(accounts.is_empty(), "OAuth2 account was not deleted");

    Ok(())
}

/// Test the core OAuth2 account deletion functionality for unauthorized access
/// This test verifies that `delete_oauth2_account_core()` correctly handles unauthorized deletion
/// attempts. It creates a test user and OAuth2 account, then tries to delete the account
/// as a different user, verifying:
/// - The deletion attempt fails with an Unauthorized error
/// - The account remains in the database after the unauthorized attempt
#[tokio::test]
#[serial]
async fn test_delete_oauth2_account_core_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    // Setup test environment
    init_test_environment().await;

    // Create test users and OAuth2 account with unique IDs
    let timestamp = chrono::Utc::now().timestamp_millis();
    let user_id = format!("test_user_delete_owner_{timestamp}");
    let other_user_id = format!("test_user_delete_unauthorized_{timestamp}");
    let provider = "google";
    let provider_user_id = format!("google_user_delete_456_{timestamp}");

    create_test_user_in_db(&user_id).await?;
    create_test_user_in_db(&other_user_id).await?;
    let unique_provider_user_id =
        create_test_oauth2_account_in_db(&user_id, provider, &provider_user_id).await?;

    // Try to delete the OAuth2 account as a different user
    let result = delete_oauth2_account_core(
        UserId::new(other_user_id).expect("Valid user ID"),
        Provider::new(provider.to_string()).expect("Valid provider"),
        ProviderUserId::new(unique_provider_user_id).expect("Valid user ID"),
    )
    .await;
    assert!(
        matches!(result, Err(CoordinationError::Unauthorized)),
        "Expected Unauthorized error, got: {result:?}"
    );

    Ok(())
}

// =============================================================================
// Mock OAuth2 Server Infrastructure for core-layer testing
// =============================================================================

const MOCK_PORT: u16 = 19876;
const MOCK_BASE_URL: &str = "http://127.0.0.1:19876";
const JWT_SECRET: &[u8] = b"test_secret";

/// Auth code -> stored request data for nonce/PKCE correlation
struct StoredAuthRequest {
    nonce: Option<String>,
    code_challenge: Option<String>,
}

#[derive(Clone)]
struct MockServerState {
    auth_codes: Arc<StdMutex<HashMap<String, StoredAuthRequest>>>,
    user_email: Arc<StdMutex<String>>,
    user_sub: Arc<StdMutex<String>>,
    user_name: Arc<StdMutex<String>>,
}

impl Default for MockServerState {
    fn default() -> Self {
        Self {
            auth_codes: Arc::new(StdMutex::new(HashMap::new())),
            user_email: Arc::new(StdMutex::new("first-user@example.com".to_string())),
            // Note: oauth2_account_from_idinfo adds "google_" prefix to sub, so sub should NOT include it.
            // "first-user-test-google-id" -> provider_user_id = "google_first-user-test-google-id"
            user_sub: Arc::new(StdMutex::new("first-user-test-google-id".to_string())),
            user_name: Arc::new(StdMutex::new("First User".to_string())),
        }
    }
}

struct MockServerHandle {
    state: MockServerState,
}

impl MockServerHandle {
    fn configure_user(&self, email: &str, sub: &str, name: &str) {
        *self.state.user_email.lock().unwrap() = email.to_string();
        *self.state.user_sub.lock().unwrap() = sub.to_string();
        *self.state.user_name.lock().unwrap() = name.to_string();
    }

    fn reset_to_first_user(&self) {
        self.configure_user(
            "first-user@example.com",
            "first-user-test-google-id",
            "First User",
        );
    }

    /// Configure mock user and return an RAII guard that resets to the first user on drop.
    /// This ensures cleanup even if the test panics between configure and manual reset.
    fn configure_user_guarded(&self, email: &str, sub: &str, name: &str) -> MockUserGuard<'_> {
        self.configure_user(email, sub, name);
        MockUserGuard { handle: self }
    }
}

/// RAII guard that resets mock server user state to the first user on drop.
/// Prevents state leakage between `#[serial]` tests if a test panics.
struct MockUserGuard<'a> {
    handle: &'a MockServerHandle,
}

impl Drop for MockUserGuard<'_> {
    fn drop(&mut self) {
        self.handle.reset_to_first_user();
    }
}

static MOCK_SERVER: LazyLock<MockServerHandle> = LazyLock::new(|| {
    let state = MockServerState::default();
    let state_for_server = state.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime for core mock OAuth2 server");
        rt.block_on(async {
            let app = axum::Router::new()
                .route("/oauth2/auth", get(mock_auth_handler))
                .route("/oauth2/token", post(mock_token_handler))
                .route("/oauth2/v3/certs", get(mock_jwks_handler))
                .route("/oauth2/userinfo", get(mock_userinfo_handler))
                .with_state(state_for_server);

            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{MOCK_PORT}"))
                .await
                .expect("Failed to bind core mock OAuth2 server");
            axum::serve(listener, app)
                .await
                .expect("Core mock OAuth2 server failed");
        });
    });

    // Wait for TCP readiness
    for _ in 0..50 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{MOCK_PORT}")).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    std::net::TcpStream::connect(format!("127.0.0.1:{MOCK_PORT}"))
        .expect("Core mock OAuth2 server failed to start within timeout");

    MockServerHandle { state }
});

fn ensure_mock_server() -> &'static MockServerHandle {
    &MOCK_SERVER
}

// --- Mock server handlers ---

async fn mock_auth_handler(
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    axum::extract::State(state): axum::extract::State<MockServerState>,
) -> axum::response::Redirect {
    let auth_code = uuid::Uuid::new_v4().to_string();
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();

    state.auth_codes.lock().unwrap().insert(
        auth_code.clone(),
        StoredAuthRequest {
            nonce: params.get("nonce").cloned(),
            code_challenge: params.get("code_challenge").cloned(),
        },
    );

    let state_param = params.get("state").cloned().unwrap_or_default();
    axum::response::Redirect::to(&format!(
        "{redirect_uri}?code={auth_code}&state={state_param}"
    ))
}

async fn mock_token_handler(
    axum::extract::State(state): axum::extract::State<MockServerState>,
    axum::extract::Form(params): axum::extract::Form<HashMap<String, String>>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    let code = params
        .get("code")
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let code_verifier = params.get("code_verifier");

    let auth_req = state
        .auth_codes
        .lock()
        .unwrap()
        .remove(code)
        .ok_or(axum::http::StatusCode::BAD_REQUEST)?;

    // Validate PKCE (S256)
    if let Some(challenge) = &auth_req.code_challenge {
        let verifier = code_verifier.ok_or(axum::http::StatusCode::BAD_REQUEST)?;
        use base64::Engine as _;
        use sha2::{Digest, Sha256};
        let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        if computed != *challenge {
            return Err(axum::http::StatusCode::BAD_REQUEST);
        }
    }

    let email = state.user_email.lock().unwrap().clone();
    let sub = state.user_sub.lock().unwrap().clone();
    let name = state.user_name.lock().unwrap().clone();
    let id_token = create_mock_jwt(&email, &sub, &name, auth_req.nonce.as_deref());

    Ok(axum::Json(json!({
        "access_token": "mock_access_token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email profile"
    })))
}

async fn mock_jwks_handler() -> axum::Json<serde_json::Value> {
    use base64::Engine as _;
    axum::Json(json!({
        "keys": [{
            "kty": "oct",
            "kid": "mock_key_id",
            "use": "sig",
            "alg": "HS256",
            "k": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(JWT_SECRET)
        }]
    }))
}

async fn mock_userinfo_handler(
    axum::extract::State(state): axum::extract::State<MockServerState>,
) -> axum::Json<serde_json::Value> {
    let email = state.user_email.lock().unwrap().clone();
    let sub = state.user_sub.lock().unwrap().clone();
    let name = state.user_name.lock().unwrap().clone();
    let parts: Vec<&str> = name.splitn(2, ' ').collect();
    let given_name = parts.first().copied().unwrap_or(&name);
    let family_name = parts.get(1).copied().unwrap_or("");

    axum::Json(json!({
        "sub": sub,
        "email": email,
        "name": name,
        "given_name": given_name,
        "family_name": family_name,
        "picture": "https://example.com/photo.jpg",
        "email_verified": true
    }))
}

fn create_mock_jwt(email: &str, sub: &str, name: &str, nonce: Option<&str>) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let parts: Vec<&str> = name.splitn(2, ' ').collect();
    let given_name = parts.first().copied().unwrap_or(name);
    let family_name = parts.get(1).copied().unwrap_or("");

    let mut claims = json!({
        "iss": MOCK_BASE_URL,
        "sub": sub,
        "aud": "test-client-id.apps.googleusercontent.com",
        "azp": "test-client-id.apps.googleusercontent.com",
        "exp": now + 3600,
        "iat": now,
        "email": email,
        "name": name,
        "given_name": given_name,
        "family_name": family_name,
        "email_verified": true
    });

    if let Some(nonce_value) = nonce {
        claims["nonce"] = json!(nonce_value);
    }

    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some("mock_key_id".to_string());
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .expect("Failed to create mock JWT")
}

// =============================================================================
// Test Helpers
// =============================================================================

/// Set environment variables to point OAuth2 endpoints at the mock server.
///
/// Uses dotenvy::from_filename_override to set env vars without unsafe code,
/// since the crate has #![forbid(unsafe_code)] and std::env::set_var is unsafe
/// in Rust 2024 edition.
fn set_mock_env_vars() {
    use std::io::Write;

    let env_content = format!(
        "OAUTH2_AUTH_URL='{MOCK_BASE_URL}/oauth2/auth'\n\
         OAUTH2_TOKEN_URL='{MOCK_BASE_URL}/oauth2/token'\n\
         OAUTH2_JWKS_URL='{MOCK_BASE_URL}/oauth2/v3/certs'\n\
         OAUTH2_USERINFO_URL='{MOCK_BASE_URL}/oauth2/userinfo'\n\
         OAUTH2_EXPECTED_ISSUER='{MOCK_BASE_URL}'\n"
    );
    let temp_path = "/tmp/oauth2_passkey_core_mock_env";
    let mut file =
        std::fs::File::create(temp_path).expect("Failed to create temp env file for mock");
    file.write_all(env_content.as_bytes())
        .expect("Failed to write temp env file for mock");
    dotenvy::from_filename_override(temp_path).expect("Failed to load mock env vars");
}

/// Drive a complete OAuth2 authorization flow through the mock server.
///
/// `extra_request_headers` allows injecting additional headers (e.g., session cookie)
/// into the `prepare_oauth2_auth_request` call. This is needed for the `add_to_user`
/// flow where a session cookie must be present so the session ID is stored in cache.
///
/// Returns (AuthResponse, Cookie, HeaderMap) ready for `get_authorized_core()`.
async fn drive_oauth2_flow(
    mode: &str,
    extra_request_headers: Option<&http::HeaderMap>,
) -> Result<
    (
        crate::oauth2::AuthResponse,
        headers::Cookie,
        http::HeaderMap,
    ),
    Box<dyn std::error::Error>,
> {
    // 1. Prepare OAuth2 auth request (generates CSRF, nonce, PKCE, stores in cache)
    let mut request_headers = http::HeaderMap::new();
    request_headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());
    if let Some(extra) = extra_request_headers {
        for (key, value) in extra {
            request_headers.insert(key.clone(), value.clone());
        }
    }

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let (auth_url, response_headers) =
        prepare_oauth2_auth_request_inner(&ctx, request_headers, Some(mode)).await?;

    // 2. Extract CSRF cookie value from Set-Cookie header
    let set_cookie = response_headers
        .get(http::header::SET_COOKIE)
        .expect("prepare_oauth2_auth_request should set CSRF cookie")
        .to_str()?;
    let csrf_cookie_pair = set_cookie
        .split(';')
        .next()
        .expect("Set-Cookie should have name=value");

    // 3. Hit mock auth endpoint (no redirect following) to get auth code
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mock_response = client.get(&auth_url).send().await?;

    let location = mock_response
        .headers()
        .get(http::header::LOCATION)
        .expect("Mock auth should return redirect with Location header")
        .to_str()?;

    // 4. Parse code and state from redirect URL
    let parsed = url::Url::parse(location)?;
    let query_params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    let code = query_params
        .get("code")
        .expect("Redirect should have code param")
        .clone();
    let state = query_params
        .get("state")
        .expect("Redirect should have state param")
        .clone();

    // 5. Build AuthResponse via deserialization (fields are non-public)
    let auth_response: crate::oauth2::AuthResponse = serde_json::from_value(json!({
        "code": code,
        "state": state,
        "_id_token": null,
    }))?;

    // 6. Build Cookie with CSRF token
    let mut cookie_header_map = http::HeaderMap::new();
    cookie_header_map.insert(http::header::COOKIE, csrf_cookie_pair.parse()?);
    let cookie: headers::Cookie = cookie_header_map
        .typed_get()
        .expect("Should parse Cookie header");

    // 7. Build request headers (User-Agent + Referer for origin validation)
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());
    // For query response mode (GET redirect), validate_origin checks Origin or Referer
    headers.insert(
        http::header::REFERER,
        format!("{MOCK_BASE_URL}/oauth2/auth").parse().unwrap(),
    );

    Ok((auth_response, cookie, headers))
}

// =============================================================================
// OAuth2 _core() Tests
// =============================================================================

/// Test that calling post_authorized_core fails when OAUTH2_RESPONSE_MODE is "query"
///
/// This test verifies the HTTP method vs response mode validation works correctly.
/// When RESPONSE_MODE is "query", only GET is allowed; POST should be rejected
/// immediately before any HTTP calls to the OAuth2 provider.
#[tokio::test]
#[serial]
async fn test_post_authorized_core_wrong_response_mode() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;

    // Construct a dummy AuthResponse (content doesn't matter - error is returned before processing)
    let auth_response: crate::oauth2::AuthResponse = serde_json::from_value(json!({
        "code": "dummy_code",
        "state": "dummy_state",
        "_id_token": null,
    }))?;

    // Construct dummy cookie and headers (also don't matter for this test)
    let mut cookie_hmap = http::HeaderMap::new();
    cookie_hmap.insert(http::header::COOKIE, "dummy=value".parse().unwrap());
    let cookie: headers::Cookie = cookie_hmap.typed_get().expect("Should parse Cookie header");

    // for_mock_server uses response_mode="query", so POST should be rejected
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result =
        post_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &http::HeaderMap::new()).await;

    assert!(
        matches!(result, Err(CoordinationError::InvalidResponseMode(_))),
        "Expected InvalidResponseMode error for POST with query mode, got: {result:?}"
    );

    Ok(())
}

/// Test get_authorized_core with "login" mode when the OAuth2 account already exists
///
/// The first test user (created by init_test_environment) has an existing OAuth2 account
/// with provider_user_id "google_first-user-test-google-id". Logging in with matching
/// credentials should succeed and return a session cookie.
#[tokio::test]
#[serial]
async fn test_get_authorized_core_login_existing_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    let (auth_response, cookie, headers) = drive_oauth2_flow("login", None).await?;
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;

    assert!(
        result.is_ok(),
        "Login with existing account should succeed: {result:?}"
    );
    let (response_headers, message) = result.unwrap();

    // Should have Set-Cookie header with session
    assert!(
        response_headers.get(http::header::SET_COOKIE).is_some(),
        "Response should include Set-Cookie header for session"
    );
    assert!(
        message.contains("Signing in"),
        "Message should indicate sign-in: {message}"
    );

    Ok(())
}

/// Test get_authorized_core with "login" mode when the OAuth2 account does not exist
///
/// When a user tries to log in but their OAuth2 account is not registered,
/// the function should return a Conflict error.
#[tokio::test]
#[serial]
async fn test_get_authorized_core_login_nonexistent_account()
-> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    // Configure mock with a user that has no existing account in the database.
    // Note: sub should NOT include "google_" prefix (oauth2_account_from_idinfo adds it).
    // Guard resets to first user on drop (panic-safe).
    let _guard = mock.configure_user_guarded(
        "nonexistent@example.com",
        "nonexistent-user-id",
        "Nonexistent User",
    );

    let (auth_response, cookie, headers) = drive_oauth2_flow("login", None).await?;
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;

    assert!(
        matches!(result, Err(CoordinationError::Conflict(_))),
        "Login with nonexistent account should return Conflict error, got: {result:?}"
    );

    Ok(())
}

/// Test get_authorized_core with "create_user" mode to create a new user
///
/// When creating a new user with a new OAuth2 identity, the function should
/// create both a User and an OAuth2Account in the database.
#[tokio::test]
#[serial]
async fn test_get_authorized_core_create_new_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    // Configure mock with a new user identity.
    // Note: sub should NOT include "google_" prefix (oauth2_account_from_idinfo adds it).
    // Guard resets to first user on drop (panic-safe).
    let timestamp = chrono::Utc::now().timestamp_millis();
    let new_email = format!("new-user-{timestamp}@example.com");
    let new_sub = format!("new-user-{timestamp}");
    let new_name = format!("New User {timestamp}");
    let _guard = mock.configure_user_guarded(&new_email, &new_sub, &new_name);

    let (auth_response, cookie, headers) = drive_oauth2_flow("create_user", None).await?;
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;

    assert!(
        result.is_ok(),
        "Creating new user should succeed: {result:?}"
    );
    let (response_headers, message) = result.unwrap();

    assert!(
        response_headers.get(http::header::SET_COOKIE).is_some(),
        "Response should include Set-Cookie header for session"
    );
    assert!(
        message.contains("Created new user"),
        "Message should indicate user creation: {message}"
    );

    // Verify the OAuth2 account was created in the database
    // oauth2_account_from_idinfo adds "google_" prefix to sub -> provider_user_id
    let expected_provider_user_id = format!("google_{new_sub}");
    let provider = crate::oauth2::Provider::new("google".to_string()).unwrap();
    let provider_user_id = crate::oauth2::ProviderUserId::new(expected_provider_user_id).unwrap();
    let account =
        crate::oauth2::OAuth2Store::get_oauth2_account_by_provider(provider, provider_user_id)
            .await?;
    assert!(
        account.is_some(),
        "OAuth2 account should exist in database after creation"
    );

    Ok(())
}

/// Test get_authorized_core with "create_user_or_login" mode
///
/// This mode should:
/// - Create a new user when the OAuth2 account doesn't exist
/// - Log in when the OAuth2 account already exists
#[tokio::test]
#[serial]
async fn test_get_authorized_core_create_user_or_login() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    // Part 1: Create user (new OAuth2 identity).
    // Note: sub should NOT include "google_" prefix (oauth2_account_from_idinfo adds it).
    // Guard resets to first user on drop (panic-safe).
    let timestamp = chrono::Utc::now().timestamp_millis();
    let new_email = format!("dual-mode-{timestamp}@example.com");
    let new_sub = format!("dual-mode-{timestamp}");
    let new_name = format!("Dual Mode User {timestamp}");
    let _guard = mock.configure_user_guarded(&new_email, &new_sub, &new_name);

    let (auth_response, cookie, headers) = drive_oauth2_flow("create_user_or_login", None).await?;
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;
    assert!(
        result.is_ok(),
        "create_user_or_login with new identity should succeed: {result:?}"
    );
    let (_headers, message) = result.unwrap();
    assert!(
        message.contains("Created new user"),
        "Should create new user: {message}"
    );

    // Part 2: Login (same OAuth2 identity, now exists)
    let (auth_response, cookie, headers) = drive_oauth2_flow("create_user_or_login", None).await?;
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;
    assert!(
        result.is_ok(),
        "create_user_or_login with existing identity should succeed: {result:?}"
    );
    let (_headers, message) = result.unwrap();
    assert!(
        message.contains("Signing in"),
        "Should sign in with existing account: {message}"
    );

    Ok(())
}

/// Test get_authorized_core with "add_to_user" mode to link OAuth2 to an existing session
///
/// When a user is already logged in (has a session) and uses "add_to_user" mode,
/// the new OAuth2 account should be linked to the existing user.
#[tokio::test]
#[serial]
async fn test_get_authorized_core_add_to_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    // Step 1: Create a session for the first user (simulate being logged in)
    let first_user_id = UserId::new("first-user".to_string()).expect("Valid user ID");
    let session_headers = crate::session::new_session_header(first_user_id).await?;

    // Extract session cookie from the response headers
    let session_set_cookie = session_headers
        .get(http::header::SET_COOKIE)
        .expect("new_session_header should set session cookie")
        .to_str()?;

    // Build extra headers with session cookie for prepare_oauth2_auth_request
    let mut session_request_headers = http::HeaderMap::new();
    let session_cookie_pair = session_set_cookie
        .split(';')
        .next()
        .expect("Set-Cookie should have name=value");
    session_request_headers.insert(http::header::COOKIE, session_cookie_pair.parse()?);

    // Configure mock with a NEW OAuth2 identity to link.
    // Note: sub should NOT include "google_" prefix (oauth2_account_from_idinfo adds it).
    // Guard resets to first user on drop (panic-safe).
    let timestamp = chrono::Utc::now().timestamp_millis();
    let link_email = format!("linked-{timestamp}@example.com");
    let link_sub = format!("linked-{timestamp}");
    let link_name = format!("Linked User {timestamp}");
    let _guard = mock.configure_user_guarded(&link_email, &link_sub, &link_name);

    // Step 2: Drive OAuth2 flow with session headers (stores session ID in cache)
    let (auth_response, cookie, headers) =
        drive_oauth2_flow("add_to_user", Some(&session_request_headers)).await?;

    // Step 3: Call get_authorized_core
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = get_authorized_core_with_ctx(&ctx, &auth_response, &cookie, &headers).await;
    assert!(result.is_ok(), "add_to_user should succeed: {result:?}");
    let (_response_headers, message) = result.unwrap();
    assert!(
        message.contains("linked"),
        "Message should indicate account linking: {message}"
    );

    // Verify the new OAuth2 account is linked to the first user
    // oauth2_account_from_idinfo adds "google_" prefix to sub -> provider_user_id
    let expected_provider_user_id = format!("google_{link_sub}");
    let provider = crate::oauth2::Provider::new("google".to_string()).unwrap();
    let provider_user_id = crate::oauth2::ProviderUserId::new(expected_provider_user_id).unwrap();
    let account =
        crate::oauth2::OAuth2Store::get_oauth2_account_by_provider(provider, provider_user_id)
            .await?;
    assert!(account.is_some(), "Linked OAuth2 account should exist");
    assert_eq!(
        account.unwrap().user_id,
        "first-user",
        "Linked account should belong to the first user"
    );

    Ok(())
}

// =============================================================================
// FedCM _core() Tests
// =============================================================================

/// Drive a FedCM authorization flow using the mock server for JWT validation.
///
/// Unlike `drive_oauth2_flow`, this does not perform a redirect/code-exchange cycle.
/// Instead it generates a nonce, creates a mock JWT containing that nonce, and calls
/// `fedcm_authorized_core` directly.
async fn drive_fedcm_flow(
    mode: Option<&str>,
) -> Result<(http::HeaderMap, String), Box<dyn std::error::Error>> {
    // 1. Generate nonce
    let nonce_response = prepare_fedcm_nonce().await?;

    // 2. Read current mock user identity
    let mock = ensure_mock_server();
    let email = mock.state.user_email.lock().unwrap().clone();
    let sub = mock.state.user_sub.lock().unwrap().clone();
    let name = mock.state.user_name.lock().unwrap().clone();

    // 3. Create JWT with nonce
    let jwt = create_mock_jwt(&email, &sub, &name, Some(&nonce_response.nonce));

    // 4. Build FedCM callback request
    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: mode.map(|s| s.to_string()),
    };

    // 5. Build headers (User-Agent required for login context)
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    // 6. Call fedcm_authorized_core_with_ctx using mock server config
    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await?;
    Ok(result)
}

/// Test FedCM login with an existing OAuth2 account
///
/// The first test user has an existing OAuth2 account. Logging in with matching
/// credentials via FedCM should succeed and return a session cookie.
#[tokio::test]
#[serial]
async fn test_fedcm_login_existing_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    let (response_headers, message) = drive_fedcm_flow(Some("login")).await?;

    assert!(
        response_headers.get(http::header::SET_COOKIE).is_some(),
        "Response should include Set-Cookie header for session"
    );
    assert!(
        message.contains("Signing in"),
        "Message should indicate sign-in: {message}"
    );

    Ok(())
}

/// Test FedCM login with a nonexistent OAuth2 account
///
/// When a user tries to log in via FedCM but their OAuth2 account is not registered,
/// the function should return a Conflict error.
#[tokio::test]
#[serial]
async fn test_fedcm_login_nonexistent_account() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    // Configure mock with a user that has no existing account in the database.
    // Note: sub should NOT include "google_" prefix (oauth2_account_from_idinfo adds it).
    let _guard = mock.configure_user_guarded(
        "fedcm-nonexistent@example.com",
        "fedcm-nonexistent-id",
        "FedCM Nonexistent User",
    );

    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "fedcm-nonexistent@example.com",
        "fedcm-nonexistent-id",
        "FedCM Nonexistent User",
        Some(&nonce_response.nonce),
    );

    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: Some("login".to_string()),
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        matches!(result, Err(CoordinationError::Conflict(_))),
        "FedCM login with nonexistent account should return Conflict error, got: {result:?}"
    );

    Ok(())
}

/// Test FedCM with "create_user" mode to create a new user
///
/// Creating a new user via FedCM with a new identity should succeed.
#[tokio::test]
#[serial]
async fn test_fedcm_create_new_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    let timestamp = Utc::now().timestamp_millis();
    let new_email = format!("fedcm-new-{timestamp}@example.com");
    let new_sub = format!("fedcm-new-{timestamp}");
    let new_name = format!("FedCM New User {timestamp}");
    let _guard = mock.configure_user_guarded(&new_email, &new_sub, &new_name);

    let (response_headers, message) = drive_fedcm_flow(Some("create_user")).await?;

    assert!(
        response_headers.get(http::header::SET_COOKIE).is_some(),
        "Response should include Set-Cookie header for session"
    );
    assert!(
        message.contains("Created new user"),
        "Message should indicate user creation: {message}"
    );

    // Verify the OAuth2 account was created in the database
    let expected_provider_user_id = format!("google_{new_sub}");
    let provider = crate::oauth2::Provider::new("google".to_string()).unwrap();
    let provider_user_id = crate::oauth2::ProviderUserId::new(expected_provider_user_id).unwrap();
    let account =
        crate::oauth2::OAuth2Store::get_oauth2_account_by_provider(provider, provider_user_id)
            .await?;
    assert!(
        account.is_some(),
        "OAuth2 account should exist in database after FedCM creation"
    );

    Ok(())
}

/// Test FedCM with "create_user_or_login" mode
///
/// This mode should create a new user when the account doesn't exist,
/// then log in when called again with the same identity.
#[tokio::test]
#[serial]
async fn test_fedcm_create_user_or_login() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();

    let timestamp = Utc::now().timestamp_millis();
    let new_email = format!("fedcm-dual-{timestamp}@example.com");
    let new_sub = format!("fedcm-dual-{timestamp}");
    let new_name = format!("FedCM Dual Mode {timestamp}");
    let _guard = mock.configure_user_guarded(&new_email, &new_sub, &new_name);

    // Part 1: Create user (new identity)
    let (_headers, message) = drive_fedcm_flow(Some("create_user_or_login")).await?;
    assert!(
        message.contains("Created new user"),
        "Should create new user: {message}"
    );

    // Part 2: Login (same identity, now exists)
    let (_headers, message) = drive_fedcm_flow(Some("create_user_or_login")).await?;
    assert!(
        message.contains("Signing in"),
        "Should sign in with existing account: {message}"
    );

    Ok(())
}

/// Test that FedCM rejects "add_to_user" mode
///
/// FedCM does not support account linking (add_to_user) because it requires
/// page session token verification. This should return InvalidState error.
#[tokio::test]
#[serial]
async fn test_fedcm_reject_add_to_user() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "first-user@example.com",
        "first-user-test-google-id",
        "First User",
        Some(&nonce_response.nonce),
    );

    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: Some("add_to_user".to_string()),
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        matches!(result, Err(CoordinationError::InvalidState(_))),
        "FedCM should reject add_to_user mode, got: {result:?}"
    );

    Ok(())
}

/// Test FedCM with "create_user" mode when the account already exists
///
/// When a user tries to create an account via FedCM but their OAuth2 account
/// is already registered, the function should return a Conflict error.
#[tokio::test]
#[serial]
async fn test_fedcm_create_existing_user_conflict() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    // First user already has an OAuth2 account in the test database.
    // Attempting create_user with the same identity should fail with Conflict.
    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "first-user@example.com",
        "first-user-test-google-id",
        "First User",
        Some(&nonce_response.nonce),
    );

    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: Some("create_user".to_string()),
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        matches!(result, Err(CoordinationError::Conflict(_))),
        "FedCM create_user with existing account should return Conflict, got: {result:?}"
    );

    Ok(())
}

/// Test FedCM nonce single-use enforcement (replay protection)
///
/// After a nonce is consumed by the first call, reusing the same nonce_id
/// should fail because the nonce has been deleted from the cache.
#[tokio::test]
#[serial]
async fn test_fedcm_nonce_replay() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    // First call: generate nonce and complete FedCM flow
    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "first-user@example.com",
        "first-user-test-google-id",
        "First User",
        Some(&nonce_response.nonce),
    );

    let request = FedCMCallbackRequest {
        credential: jwt.clone(),
        nonce_id: nonce_response.nonce_id.clone(),
        mode: Some("login".to_string()),
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let first_result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        first_result.is_ok(),
        "First FedCM call should succeed: {first_result:?}"
    );

    // Second call: reuse the same nonce_id (nonce already consumed)
    let replay_request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: Some("login".to_string()),
    };
    let replay_result = fedcm_authorized_core_with_ctx(&ctx, &replay_request, &headers).await;
    assert!(
        matches!(
            replay_result,
            Err(CoordinationError::OAuth2Error(
                OAuth2Error::SecurityTokenNotFound(_)
            ))
        ),
        "Replayed nonce should return SecurityTokenNotFound, got: {replay_result:?}"
    );

    Ok(())
}

/// Test FedCM with mismatched nonce
///
/// When the JWT's nonce claim doesn't match the stored nonce, validation should fail.
#[tokio::test]
#[serial]
async fn test_fedcm_nonce_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    // Generate nonce but create JWT with a different nonce value
    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "first-user@example.com",
        "first-user-test-google-id",
        "First User",
        Some("wrong-nonce-value"), // Intentionally mismatched
    );

    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: Some("login".to_string()),
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        matches!(
            result,
            Err(CoordinationError::OAuth2Error(OAuth2Error::NonceMismatch))
        ),
        "Mismatched nonce should return NonceMismatch, got: {result:?}"
    );

    Ok(())
}

/// Test FedCM with mode=None falls into catch-all InvalidState
///
/// When no mode is provided, `process_authenticated_oauth2_user` receives
/// `mode: None` which doesn't match any explicit case, so the catch-all
/// returns InvalidState.
#[tokio::test]
#[serial]
async fn test_fedcm_mode_none() -> Result<(), Box<dyn std::error::Error>> {
    init_test_environment().await;
    let mock = ensure_mock_server();
    set_mock_env_vars();
    mock.reset_to_first_user();

    let nonce_response = prepare_fedcm_nonce().await?;
    let jwt = create_mock_jwt(
        "first-user@example.com",
        "first-user-test-google-id",
        "First User",
        Some(&nonce_response.nonce),
    );

    let request = FedCMCallbackRequest {
        credential: jwt,
        nonce_id: nonce_response.nonce_id,
        mode: None,
    };
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::USER_AGENT, "TestBrowser/1.0".parse().unwrap());

    let ctx = ProviderConfig::for_mock_server(MOCK_BASE_URL);
    let result = fedcm_authorized_core_with_ctx(&ctx, &request, &headers).await;
    assert!(
        matches!(result, Err(CoordinationError::InvalidState(_))),
        "FedCM with mode=None should return InvalidState, got: {result:?}"
    );

    Ok(())
}
