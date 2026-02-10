use serde::{Deserialize, Serialize};
use thiserror::Error;

/// OIDC Discovery Document as defined by OpenID Connect Discovery 1.0 specification
/// https://openid.net/specs/openid-connect-discovery-1_0.html
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct OidcDiscoveryDocument {
    /// The issuer identifier for the OpenID Provider
    pub issuer: String,
    /// URL of the OAuth 2.0 Authorization Endpoint
    pub authorization_endpoint: String,
    /// URL of the OAuth 2.0 Token Endpoint
    pub token_endpoint: String,
    /// URL of the UserInfo Endpoint
    pub userinfo_endpoint: String,
    /// URL of the JSON Web Key Set
    pub jwks_uri: String,
    /// List of the OAuth 2.0 scope values supported
    pub scopes_supported: Option<Vec<String>>,
    /// List of the OAuth 2.0 response_type values supported
    pub response_types_supported: Option<Vec<String>>,
    /// List of the OAuth 2.0 Grant Type values supported
    pub grant_types_supported: Option<Vec<String>>,
    /// List of the Subject Identifier types supported
    pub subject_types_supported: Option<Vec<String>>,
    /// List of the JWS signing algorithms supported for ID tokens
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// Errors that can occur during OIDC discovery
#[derive(Error, Debug, Clone)]
pub enum OidcDiscoveryError {
    #[error("HTTP request failed: {0}")]
    HttpError(String),
    #[error("HTTP status error: {0}")]
    HttpStatusError(reqwest::StatusCode),
    #[error("JSON parsing failed: {0}")]
    JsonError(String),
    #[error("Issuer mismatch: discovered={0}, expected={1}")]
    IssuerMismatch(String, String),
    #[error("Invalid discovery URL: {0}")]
    InvalidUrl(String),
    #[error("Cache error: {0}")]
    CacheError(String),
}

impl From<reqwest::Error> for OidcDiscoveryError {
    fn from(err: reqwest::Error) -> Self {
        Self::HttpError(err.to_string())
    }
}

impl From<serde_json::Error> for OidcDiscoveryError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err.to_string())
    }
}

/// Fetch OIDC discovery document from the well-known endpoint
///
/// According to the OIDC Discovery specification, the discovery document
/// is available at: {issuer}/.well-known/openid-configuration
pub(crate) async fn fetch_oidc_discovery(
    issuer_url: &str,
) -> Result<OidcDiscoveryDocument, OidcDiscoveryError> {
    let issuer_url = issuer_url.trim_end_matches('/');
    let discovery_url = format!("{issuer_url}/.well-known/openid-configuration");

    tracing::debug!("Fetching OIDC discovery from: {}", discovery_url);

    let client = super::main::get_client();

    let response = client.get(&discovery_url).send().await?;

    if !response.status().is_success() {
        tracing::error!("OIDC discovery failed with status: {}", response.status());
        return Err(OidcDiscoveryError::HttpStatusError(response.status()));
    }

    let document: OidcDiscoveryDocument = response.json().await?;

    // Validate that the issuer in the document matches the expected issuer
    // This is a security requirement per OIDC specification
    if document.issuer != issuer_url {
        tracing::error!(
            "Issuer mismatch in discovery document. Expected: {}, Found: {}",
            issuer_url,
            document.issuer
        );
        return Err(OidcDiscoveryError::IssuerMismatch(
            document.issuer,
            issuer_url.to_string(),
        ));
    }

    tracing::debug!("Successfully fetched OIDC discovery document");
    tracing::debug!(
        "Authorization endpoint: {}",
        document.authorization_endpoint
    );
    tracing::debug!("Token endpoint: {}", document.token_endpoint);
    tracing::debug!("JWKS URI: {}", document.jwks_uri);

    Ok(document)
}

#[cfg(test)]
mod tests;
