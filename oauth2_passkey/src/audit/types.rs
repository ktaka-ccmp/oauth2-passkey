//! Types for login history tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;

/// Authentication method used for login
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
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

impl AuthMethod {
    /// Parse auth method from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "passkey" => Some(AuthMethod::Passkey),
            "oauth2" => Some(AuthMethod::OAuth2),
            _ => None,
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
    pub fn success(
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
    pub fn failure(
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
pub struct LoginContext {
    /// IP address from request headers
    pub ip_address: Option<String>,
    /// User-Agent from request headers
    pub user_agent: Option<String>,
}

impl LoginContext {
    /// Create a new login context
    pub fn new(ip_address: Option<String>, user_agent: Option<String>) -> Self {
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

/// Query parameters for fetching login history
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct LoginHistoryQuery {
    /// User ID to fetch history for
    pub user_id: String,
    /// Maximum number of entries to return
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

#[allow(dead_code)]
impl LoginHistoryQuery {
    /// Create a new query with defaults
    pub fn new(user_id: String) -> Self {
        Self {
            user_id,
            limit: Some(50),
            offset: Some(0),
        }
    }

    /// Set limit
    pub fn with_limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set offset
    pub fn with_offset(mut self, offset: i64) -> Self {
        self.offset = Some(offset);
        self
    }
}
