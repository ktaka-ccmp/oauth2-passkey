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
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> =
    LazyLock::new(|| match std::env::var("SESSION_COOKIE_MAX_AGE") {
        Ok(val) => val
            .parse()
            .unwrap_or_else(|e| panic!("SESSION_COOKIE_MAX_AGE='{val}' is not a valid u64: {e}")),
        Err(_) => 600,
    });

/// Domain attribute for session cookies.
///
/// When set, cookies will be shared across subdomains of the specified domain.
/// For example, setting `.example.com` allows cookies to be shared between
/// `app.example.com` and `api.example.com`.
///
/// **Important**: When using a domain attribute, the cookie name should NOT use
/// the `__Host-` prefix, as `__Host-` cookies cannot have a Domain attribute.
/// Use `SESSION_COOKIE_NAME` to set a custom name without the prefix.
///
/// Configured via the `SESSION_COOKIE_DOMAIN` environment variable.
/// Default: None (no Domain attribute, same-origin only)
pub static SESSION_COOKIE_DOMAIN: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("SESSION_COOKIE_DOMAIN").ok());

/// Policy for handling session conflicts when a user logs in while already having active sessions.
///
/// This policy is always evaluated during login, and user_id -> session_id mappings
/// are always maintained regardless of the policy value. The policy only controls
/// what happens when existing sessions are found.
///
/// Configured via the `SESSION_CONFLICT_POLICY` environment variable.
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
/// Set via the `SESSION_CONFLICT_POLICY` environment variable.
///
/// Valid values:
/// - `allow` (default): Permit multiple concurrent sessions
/// - `replace`: Invalidate all existing sessions, create new one
/// - `reject`: Deny login if active session exists
pub static SESSION_CONFLICT_POLICY: LazyLock<SessionConflictPolicy> =
    LazyLock::new(|| match env::var("SESSION_CONFLICT_POLICY") {
        Err(_) => SessionConflictPolicy::Allow,
        Ok(val) => match val.to_lowercase().as_str() {
            "allow" => SessionConflictPolicy::Allow,
            "replace" => SessionConflictPolicy::Replace,
            "reject" => SessionConflictPolicy::Reject,
            _ => panic!(
                "SESSION_CONFLICT_POLICY='{val}' is invalid. Valid values: allow, replace, reject"
            ),
        },
    });

/// TTL for user session mappings in seconds (30 days).
///
/// The user_id -> session_id[] mapping needs a long TTL because it tracks
/// all active sessions for a user. Individual sessions expire via their own TTL,
/// and stale entries are cleaned up lazily when the mapping is read.
pub(super) const USER_SESSIONS_MAPPING_TTL: u64 = 86400 * 30;

/// Secret key for HMAC signing of page session tokens.
///
/// When set via `AUTH_SERVER_SECRET` env var, uses that value.
/// When not set, generates a random 32-byte key at startup.
///
/// **Important**: In multi-process deployments (e.g., behind a load balancer),
/// all processes must share the same secret. Set `AUTH_SERVER_SECRET` explicitly.
/// A random default only works for single-process deployments.
pub(super) static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> =
    LazyLock::new(|| match env::var("AUTH_SERVER_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => {
            use ring::rand::SecureRandom;
            let rng = ring::rand::SystemRandom::new();
            let mut secret = vec![0u8; 32];
            rng.fill(&mut secret)
                .expect("Failed to generate random AUTH_SERVER_SECRET");
            tracing::info!("AUTH_SERVER_SECRET not set, using random key (single-process only)");
            secret
        }
    });
