use std::env;
use std::sync::LazyLock;

/// Name of the session cookie used for authentication.
///
/// By default, uses the secure "__Host-" prefix to enforce additional security constraints.
/// Can be configured via the SESSION_COOKIE_NAME environment variable.
///
/// The "__Host-" prefix ensures that cookies:
/// 1. Cannot be set from a non-secure context
/// 2. Must have the Path attribute set to "/"
/// 3. Cannot include a Domain attribute (preventing subdomain access)
pub static SESSION_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-SessionId".to_string())
});
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600) // Default to 10 minutes if not set or invalid
});

/// Policy for handling session conflicts when a user logs in while already having active sessions.
///
/// This policy is always evaluated during login, and user_id -> session_id mappings
/// are always maintained regardless of the policy value. The policy only controls
/// what happens when existing sessions are found.
///
/// Configured via the `O2P_SESSION_CONFLICT_POLICY` environment variable.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionConflictPolicy {
    /// Allow multiple concurrent sessions (default)
    Allow,
    /// Invalidate all existing sessions and create a new one
    Replace,
    /// Deny login if an active session already exists
    Reject,
}

/// Session conflict policy configuration.
///
/// Controls what happens when a user logs in while already having active sessions.
/// Set via the `O2P_SESSION_CONFLICT_POLICY` environment variable.
///
/// Valid values:
/// - `allow` (default): Permit multiple concurrent sessions
/// - `replace`: Invalidate all existing sessions, create new one
/// - `reject`: Deny login if active session exists
pub static O2P_SESSION_CONFLICT_POLICY: LazyLock<SessionConflictPolicy> = LazyLock::new(|| {
    match env::var("O2P_SESSION_CONFLICT_POLICY")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "replace" => SessionConflictPolicy::Replace,
        "reject" => SessionConflictPolicy::Reject,
        _ => SessionConflictPolicy::Allow,
    }
});

/// TTL for user session mappings in seconds (30 days).
///
/// The user_id -> session_id[] mapping needs a long TTL because it tracks
/// all active sessions for a user. Individual sessions expire via their own TTL,
/// and stale entries are cleaned up lazily when the mapping is read.
pub(super) const USER_SESSIONS_MAPPING_TTL: u64 = 86400 * 30;

// We're using a simple string representation for tokens instead of a struct
// to minimize dependencies and complexity

pub(super) static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> =
    LazyLock::new(|| match env::var("AUTH_SERVER_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => "default_secret_key_change_in_production"
            .to_string()
            .into_bytes(),
    });
