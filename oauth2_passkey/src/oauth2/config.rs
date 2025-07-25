use super::discovery::{OidcDiscoveryDocument, OidcDiscoveryError, fetch_oidc_discovery};
use crate::config::O2P_ROUTE_PREFIX;
use std::{
    env,
    sync::{LazyLock, OnceLock},
};

/// Base issuer URL for OIDC discovery
/// Set this to enable automatic discovery of OAuth2 endpoints
pub(crate) static OAUTH2_ISSUER_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_ISSUER_URL")
        .ok()
        .unwrap_or("https://accounts.google.com".to_string())
});

/// Cache for discovered OIDC endpoints
/// This is populated on first use and cached for the lifetime of the application
static OIDC_DISCOVERY_CACHE: OnceLock<OidcDiscoveryDocument> = OnceLock::new();

/// Get discovered OIDC endpoints, fetching from the issuer's well-known endpoint if not cached
pub(crate) async fn get_discovered_endpoints()
-> Result<&'static OidcDiscoveryDocument, OidcDiscoveryError> {
    // Return cached version if available
    if let Some(cached) = OIDC_DISCOVERY_CACHE.get() {
        return Ok(cached);
    }

    // Fetch discovery document
    tracing::debug!("Fetching OIDC discovery for issuer: {}", *OAUTH2_ISSUER_URL);
    let document = fetch_oidc_discovery(&OAUTH2_ISSUER_URL).await?;

    // Store in cache (first write wins in case of concurrent access)
    let _ = OIDC_DISCOVERY_CACHE.set(document);

    // Return the cached version - this should always succeed since either we just set it
    // or another thread set it between our check and now
    OIDC_DISCOVERY_CACHE.get().ok_or_else(|| {
        OidcDiscoveryError::CacheError("Failed to cache discovery document".to_string())
    })
}

/// Get authorization URL, using discovery if no environment override is set
pub(crate) async fn get_auth_url() -> Result<String, OidcDiscoveryError> {
    // Check for environment variable override first
    if let Ok(env_url) = env::var("OAUTH2_AUTH_URL") {
        tracing::debug!("Using OAUTH2_AUTH_URL from environment: {}", env_url);
        return Ok(env_url);
    }

    // Use discovery
    let endpoints = get_discovered_endpoints().await?;
    tracing::debug!(
        "Using authorization endpoint from discovery: {}",
        endpoints.authorization_endpoint
    );
    Ok(endpoints.authorization_endpoint.clone())
}

/// Get token URL, using discovery if no environment override is set
pub(crate) async fn get_token_url() -> Result<String, OidcDiscoveryError> {
    // Check for environment variable override first
    if let Ok(env_url) = env::var("OAUTH2_TOKEN_URL") {
        tracing::debug!("Using OAUTH2_TOKEN_URL from environment: {}", env_url);
        return Ok(env_url);
    }

    // Use discovery
    let endpoints = get_discovered_endpoints().await?;
    tracing::debug!(
        "Using token endpoint from discovery: {}",
        endpoints.token_endpoint
    );
    Ok(endpoints.token_endpoint.clone())
}

/// Get userinfo URL, using discovery if no environment override is set
pub(crate) async fn get_userinfo_url() -> Result<String, OidcDiscoveryError> {
    // Check for environment variable override first
    if let Ok(env_url) = env::var("OAUTH2_USERINFO_URL") {
        tracing::debug!("Using OAUTH2_USERINFO_URL from environment: {}", env_url);
        return Ok(env_url);
    }

    // Use discovery
    let endpoints = get_discovered_endpoints().await?;
    tracing::debug!(
        "Using userinfo endpoint from discovery: {}",
        endpoints.userinfo_endpoint
    );
    Ok(endpoints.userinfo_endpoint.clone())
}

/// Get JWKS URL, using discovery if no environment override is set
pub(crate) async fn get_jwks_url() -> Result<String, OidcDiscoveryError> {
    // Check for environment variable override first
    if let Ok(env_url) = env::var("OAUTH2_JWKS_URL") {
        tracing::debug!("Using OAUTH2_JWKS_URL from environment: {}", env_url);
        return Ok(env_url);
    }

    // Use discovery
    let endpoints = get_discovered_endpoints().await?;
    tracing::debug!("Using JWKS URI from discovery: {}", endpoints.jwks_uri);
    Ok(endpoints.jwks_uri.clone())
}

/// Get expected issuer, using discovery if no environment override is set
pub(crate) async fn get_expected_issuer() -> Result<String, OidcDiscoveryError> {
    // Check for environment variable override first
    if let Ok(env_issuer) = env::var("OAUTH2_EXPECTED_ISSUER") {
        tracing::debug!(
            "Using OAUTH2_EXPECTED_ISSUER from environment: {}",
            env_issuer
        );
        return Ok(env_issuer);
    }

    // Use discovery
    let endpoints = get_discovered_endpoints().await?;
    tracing::debug!("Using issuer from discovery: {}", endpoints.issuer);
    Ok(endpoints.issuer.clone())
}

static OAUTH2_SCOPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string()));

pub(crate) static OAUTH2_RESPONSE_MODE: LazyLock<String> = LazyLock::new(|| {
    let mode = std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
    match mode.to_lowercase().as_str() {
        "form_post" => "form_post".to_string(),
        "query" => "query".to_string(),
        _ => {
            panic!("Invalid OAUTH2_RESPONSE_MODE '{mode}'. Must be 'form_post' or 'query'.");
        }
    }
});

static OAUTH2_RESPONSE_TYPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string()));

pub(crate) static OAUTH2_QUERY_STRING: LazyLock<String> = LazyLock::new(|| {
    let mut query_string = "".to_string();
    query_string.push_str(&format!("&response_type={}", *OAUTH2_RESPONSE_TYPE));
    query_string.push_str(&format!("&scope={}", *OAUTH2_SCOPE));
    query_string.push_str(&format!("&response_mode={}", *OAUTH2_RESPONSE_MODE));
    query_string.push_str(&format!("&access_type={}", "online"));
    query_string.push_str(&format!("&prompt={}", "consent"));
    query_string
});

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".

pub(crate) static OAUTH2_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub(super) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 60 seconds if not set or invalid
});

pub(super) static OAUTH2_REDIRECT_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}{}/oauth2/authorized",
        env::var("ORIGIN").expect("Missing ORIGIN!"),
        O2P_ROUTE_PREFIX.as_str()
    )
});

pub(super) static OAUTH2_GOOGLE_CLIENT_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set")
});

pub(super) static OAUTH2_GOOGLE_CLIENT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set")
});

// URL resolution logic is tested through integration tests.
// The precedence logic (environment variables > OIDC Discovery) is evident from the code structure.
