//! Types for login history tracking

use chrono::{DateTime, Utc};
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;

/// Authentication method used for login
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuthMethod {
    Passkey,
    OAuth2,
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthMethod::Passkey => write!(f, "passkey"),
            AuthMethod::OAuth2 => write!(f, "oauth2"),
        }
    }
}

/// A single login history entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct LoginHistoryEntry {
    /// Database ID (auto-generated)
    pub id: Option<i64>,
    /// User ID who logged in
    pub user_id: String,
    /// Timestamp of the login attempt
    pub timestamp: DateTime<Utc>,
    /// Authentication method used (passkey/oauth2)
    pub auth_method: String,
    /// IP address of the client (may be None for privacy)
    pub ip_address: Option<String>,
    /// User-Agent header (truncated)
    pub user_agent: Option<String>,
    /// Whether the login was successful
    pub success: bool,
    /// Passkey credential ID (for passkey logins)
    pub credential_id: Option<String>,
    /// OAuth2 provider name (for OAuth2 logins)
    pub provider: Option<String>,
    /// OAuth2 provider user ID (for OAuth2 logins)
    pub provider_user_id: Option<String>,
    /// Reason for failure (if success is false)
    pub failure_reason: Option<String>,
}

impl LoginHistoryEntry {
    /// Create a new login history entry for a successful login
    pub(crate) fn success(
        user_id: String,
        auth_method: AuthMethod,
        context: LoginContext,
        credential_id: Option<String>,
        provider: Option<String>,
        provider_user_id: Option<String>,
    ) -> Self {
        Self {
            id: None,
            user_id,
            timestamp: Utc::now(),
            auth_method: auth_method.to_string(),
            ip_address: context.ip_address,
            user_agent: context.user_agent.map(|ua| truncate_user_agent(&ua)),
            success: true,
            credential_id,
            provider,
            provider_user_id,
            failure_reason: None,
        }
    }

    /// Create a new login history entry for a failed login
    pub(crate) fn failure(
        user_id: String,
        auth_method: AuthMethod,
        context: LoginContext,
        credential_id: Option<String>,
        reason: String,
    ) -> Self {
        Self {
            id: None,
            user_id,
            timestamp: Utc::now(),
            auth_method: auth_method.to_string(),
            ip_address: context.ip_address,
            user_agent: context.user_agent.map(|ua| truncate_user_agent(&ua)),
            success: false,
            credential_id,
            provider: None,
            provider_user_id: None,
            failure_reason: Some(reason),
        }
    }

    /// Mask IP address for user view (hide last octet)
    pub fn masked_ip(&self) -> Option<String> {
        self.ip_address.as_ref().map(|ip| {
            if let Some(pos) = ip.rfind('.') {
                format!("{}.*", &ip[..pos])
            } else if let Some(pos) = ip.rfind(':') {
                // IPv6: mask last segment
                format!("{}:*", &ip[..pos])
            } else {
                ip.clone()
            }
        })
    }
}

/// Context information for a login attempt
#[derive(Debug, Clone, Default)]
pub(crate) struct LoginContext {
    /// IP address from request headers
    ip_address: Option<String>,
    /// User-Agent from request headers
    user_agent: Option<String>,
}

impl LoginContext {
    /// Extract login context from HTTP headers
    ///
    /// Extracts the client IP address (from X-Forwarded-For or X-Real-IP headers)
    /// and User-Agent for recording in the login history.
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        let ip_address = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            });

        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Self {
            ip_address,
            user_agent,
        }
    }
}

/// Truncate user agent to reasonable length
fn truncate_user_agent(ua: &str) -> String {
    const MAX_LENGTH: usize = 512;
    if ua.len() > MAX_LENGTH {
        ua[..MAX_LENGTH].to_string()
    } else {
        ua.to_string()
    }
}
