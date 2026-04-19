use std::{
    env,
    sync::{LazyLock, OnceLock},
};

use crate::config::O2P_ROUTE_PREFIX;
use crate::oauth2::discovery::{OidcDiscoveryDocument, OidcDiscoveryError, fetch_oidc_discovery};

/// Identifies a supported OAuth2/OIDC provider.
///
/// Adding a new provider requires these lock-step edits, all in this file:
/// 1. A new variant in `ProviderKind`
/// 2. Include it in `ProviderKind::ALL`
/// 3. A new arm in `as_str`
/// 4. A new arm in `from_path_segment`
/// 5. A corresponding static (`LazyLock<ProviderConfig>` or
///    `LazyLock<Option<ProviderConfig>>`) and a new arm in `provider_for`
/// 6. If the provider is optional, return its env-var contract from
///    `optional_env_contract` so startup validation catches the
///    "trigger set but dependent missing" case
///
/// Reserved names that must never become enum variants (they collide with
/// existing literal routes under `/oauth2/*`):
/// "authorized", "accounts", "fedcm", "popup_close", "oauth2.js"
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProviderKind {
    Google,
    Auth0,
    Keycloak,
}

impl ProviderKind {
    /// All supported provider kinds in stable display order.
    pub(crate) const ALL: &'static [Self] = &[Self::Google, Self::Auth0, Self::Keycloak];

    /// Env-var validation contract for optional providers.
    ///
    /// Returns `Some((trigger, dependents))` for providers activated by one
    /// env var that require additional env vars when that trigger is set.
    /// Returns `None` for unconditional providers (validated directly in `init`).
    ///
    /// Used by `init` to fail fast at startup instead of panicking mid-request
    /// via the `LazyLock.expect()` inside the matching static.
    pub(crate) fn optional_env_contract(&self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Self::Google => None,
            Self::Auth0 => Some((
                "OAUTH2_AUTH0_CLIENT_ID",
                &["OAUTH2_AUTH0_CLIENT_SECRET", "OAUTH2_AUTH0_ISSUER_URL"],
            )),
            Self::Keycloak => Some((
                "OAUTH2_KEYCLOAK_CLIENT_ID",
                &[
                    "OAUTH2_KEYCLOAK_CLIENT_SECRET",
                    "OAUTH2_KEYCLOAK_ISSUER_URL",
                ],
            )),
        }
    }

    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Auth0 => "auth0",
            Self::Keycloak => "keycloak",
        }
    }

    /// Parse a URL path segment (e.g. "google") into a `ProviderKind`.
    /// Returns `None` for unsupported values.
    pub(crate) fn from_path_segment(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Self::Google),
            "auth0" => Some(Self::Auth0),
            "keycloak" => Some(Self::Keycloak),
            _ => None,
        }
    }
}

/// Public information about a single enabled OAuth2 provider.
///
/// Returned by [`enabled_providers`](crate::oauth2::enabled_providers).
/// Carries only the protocol identifier for this provider — presentation data
/// (human-readable label, CSS classes) lives in the axum integration crate's
/// `ProviderView`.  Future protocol-level attributes (e.g. `supports_pkce`,
/// `is_oidc`) can be added here as non-breaking field additions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProviderInfo {
    /// URL path segment used in OAuth2 state, DB rows, and route matching
    /// (e.g. `"google"`, `"auth0"`).
    pub name: &'static str,
}

impl std::fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-provider OAuth2/OIDC configuration.
///
/// Each instance holds all configuration needed for one provider:
/// credentials, computed endpoint URLs (via per-instance OIDC discovery),
/// and response-mode settings.
///
/// The `discovery` field uses `OnceLock` with a "first write wins" strategy,
/// matching the existing global `OIDC_DISCOVERY_CACHE` behaviour.  Concurrent
/// first-access races may cause redundant fetches but always result in
/// correct state.
///
/// **`ProviderConfig` is `pub(crate)`**: it never appears in the public API of
/// `oauth2_passkey`.  The axum-crate boundary uses `&str`; parsing and config
/// resolution happen inside this crate.
pub(crate) struct ProviderConfig {
    pub(crate) kind: ProviderKind,
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    /// Base issuer URL used for OIDC discovery (trailing slash stripped).
    pub(crate) issuer_url: String,
    /// Redirect URI registered in the IdP console.
    /// Built as `{ORIGIN}{O2P_ROUTE_PREFIX}/oauth2/{provider}/authorized`.
    pub(crate) redirect_uri: String,
    pub(crate) response_mode: String,
    /// Precomputed query-string fragment appended to the authorization URL.
    /// Starts with `&` to match the existing format string in core.rs.
    pub(crate) query_string: String,
    /// Per-provider OIDC discovery document cache.
    pub(crate) discovery: OnceLock<OidcDiscoveryDocument>,
}

impl ProviderConfig {
    async fn get_or_fetch_discovery(&self) -> Result<&OidcDiscoveryDocument, OidcDiscoveryError> {
        if let Some(cached) = self.discovery.get() {
            return Ok(cached);
        }

        tracing::debug!(
            provider = %self.kind,
            "Fetching OIDC discovery for issuer: {}",
            self.issuer_url
        );
        let document = fetch_oidc_discovery(&self.issuer_url).await?;

        // First write wins in case of concurrent access
        let _ = self.discovery.set(document);

        self.discovery.get().ok_or_else(|| {
            OidcDiscoveryError::CacheError("Failed to cache discovery document".to_string())
        })
    }

    pub(crate) async fn auth_url(&self) -> Result<String, OidcDiscoveryError> {
        let doc = self.get_or_fetch_discovery().await?;
        Ok(doc.authorization_endpoint.clone())
    }

    pub(crate) async fn token_url(&self) -> Result<String, OidcDiscoveryError> {
        let doc = self.get_or_fetch_discovery().await?;
        Ok(doc.token_endpoint.clone())
    }

    pub(crate) async fn jwks_url(&self) -> Result<String, OidcDiscoveryError> {
        let doc = self.get_or_fetch_discovery().await?;
        Ok(doc.jwks_uri.clone())
    }

    pub(crate) async fn userinfo_url(&self) -> Result<String, OidcDiscoveryError> {
        let doc = self.get_or_fetch_discovery().await?;
        Ok(doc.userinfo_endpoint.clone())
    }

    pub(crate) async fn expected_issuer(&self) -> Result<String, OidcDiscoveryError> {
        let doc = self.get_or_fetch_discovery().await?;
        Ok(doc.issuer.clone())
    }
}

/// Google provider — unconditional (panics at first access if env vars are missing,
/// matching the previous `LazyLock<String>` behaviour).
pub(crate) static GOOGLE_PROVIDER: LazyLock<ProviderConfig> = LazyLock::new(|| {
    let client_id =
        env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set");
    let client_secret =
        env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set");
    let issuer_url =
        env::var("OAUTH2_ISSUER_URL").unwrap_or_else(|_| "https://accounts.google.com".to_string());
    let origin = env::var("ORIGIN").expect("Missing ORIGIN!");
    let redirect_uri = format!(
        "{}{}/oauth2/google/authorized",
        origin,
        O2P_ROUTE_PREFIX.as_str()
    );
    let response_mode = {
        let mode = env::var("OAUTH2_RESPONSE_MODE").unwrap_or_else(|_| "form_post".to_string());
        match mode.to_lowercase().as_str() {
            "form_post" => "form_post".to_string(),
            "query" => "query".to_string(),
            _ => panic!("Invalid OAUTH2_RESPONSE_MODE '{mode}'. Must be 'form_post' or 'query'."),
        }
    };
    let scope = env::var("OAUTH2_SCOPE").unwrap_or_else(|_| "openid+email+profile".to_string());
    let response_type = env::var("OAUTH2_RESPONSE_TYPE").unwrap_or_else(|_| "code".to_string());
    let query_string = format!(
        "&response_type={}&scope={}&response_mode={}&access_type=online&prompt=consent",
        response_type, scope, response_mode
    );
    ProviderConfig {
        kind: ProviderKind::Google,
        client_id,
        client_secret,
        issuer_url,
        redirect_uri,
        response_mode,
        query_string,
        discovery: OnceLock::new(),
    }
});

/// Auth0 provider — optional, enabled by setting `OAUTH2_AUTH0_CLIENT_ID`.
/// Panics at first access if `CLIENT_ID` is set but `CLIENT_SECRET` or
/// `ISSUER_URL` are missing (mis-configured, not intentionally absent).
pub(crate) static AUTH0_PROVIDER: LazyLock<Option<ProviderConfig>> = LazyLock::new(|| {
    let client_id = env::var("OAUTH2_AUTH0_CLIENT_ID").ok()?;
    let client_secret = env::var("OAUTH2_AUTH0_CLIENT_SECRET")
        .expect("OAUTH2_AUTH0_CLIENT_ID set but OAUTH2_AUTH0_CLIENT_SECRET missing");
    let issuer_url = env::var("OAUTH2_AUTH0_ISSUER_URL")
        .expect("OAUTH2_AUTH0_CLIENT_ID set but OAUTH2_AUTH0_ISSUER_URL missing");
    let origin = env::var("ORIGIN").expect("Missing ORIGIN!");
    let redirect_uri = format!(
        "{}{}/oauth2/auth0/authorized",
        origin,
        O2P_ROUTE_PREFIX.as_str()
    );
    let response_mode =
        env::var("OAUTH2_AUTH0_RESPONSE_MODE").unwrap_or_else(|_| "form_post".to_string());
    let scope =
        env::var("OAUTH2_AUTH0_SCOPE").unwrap_or_else(|_| "openid+email+profile".to_string());
    // Note: `access_type=online` is Google-specific and omitted here.
    let query_string = format!(
        "&response_type=code&scope={}&response_mode={}&prompt=consent",
        scope, response_mode
    );
    Some(ProviderConfig {
        kind: ProviderKind::Auth0,
        client_id,
        client_secret,
        issuer_url,
        redirect_uri,
        response_mode,
        query_string,
        discovery: OnceLock::new(),
    })
});

/// Keycloak provider — optional, enabled by setting `OAUTH2_KEYCLOAK_CLIENT_ID`.
/// Issuer URL format: `http(s)://{host}/realms/{realm-name}` (no trailing slash).
pub(crate) static KEYCLOAK_PROVIDER: LazyLock<Option<ProviderConfig>> = LazyLock::new(|| {
    let client_id = env::var("OAUTH2_KEYCLOAK_CLIENT_ID").ok()?;
    let client_secret = env::var("OAUTH2_KEYCLOAK_CLIENT_SECRET")
        .expect("OAUTH2_KEYCLOAK_CLIENT_ID set but OAUTH2_KEYCLOAK_CLIENT_SECRET missing");
    let issuer_url = env::var("OAUTH2_KEYCLOAK_ISSUER_URL")
        .expect("OAUTH2_KEYCLOAK_CLIENT_ID set but OAUTH2_KEYCLOAK_ISSUER_URL missing");
    let origin = env::var("ORIGIN").expect("Missing ORIGIN!");
    let redirect_uri = format!(
        "{}{}/oauth2/keycloak/authorized",
        origin,
        O2P_ROUTE_PREFIX.as_str()
    );
    let response_mode =
        env::var("OAUTH2_KEYCLOAK_RESPONSE_MODE").unwrap_or_else(|_| "form_post".to_string());
    let scope =
        env::var("OAUTH2_KEYCLOAK_SCOPE").unwrap_or_else(|_| "openid+email+profile".to_string());
    let query_string = format!(
        "&response_type=code&scope={}&response_mode={}&prompt=consent",
        scope, response_mode
    );
    Some(ProviderConfig {
        kind: ProviderKind::Keycloak,
        client_id,
        client_secret,
        issuer_url,
        redirect_uri,
        response_mode,
        query_string,
        discovery: OnceLock::new(),
    })
});

/// Resolve a `ProviderKind` to its `&'static ProviderConfig`.
///
/// Returns `None` if the provider is optional and not configured (its env vars
/// are absent).  Google is unconditional, so this always returns `Some` for it.
pub(crate) fn provider_for(kind: ProviderKind) -> Option<&'static ProviderConfig> {
    match kind {
        ProviderKind::Google => Some(&GOOGLE_PROVIDER),
        ProviderKind::Auth0 => AUTH0_PROVIDER.as_ref(),
        ProviderKind::Keycloak => KEYCLOAK_PROVIDER.as_ref(),
    }
}

#[cfg(test)]
mod tests;
