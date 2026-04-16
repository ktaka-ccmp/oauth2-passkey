use std::sync::LazyLock;

// "__Host-" prefix forces host-only cookies (no Domain attribute, Secure flag required).

/// CSRF cookie name used for the OAuth2 flow CSRF protection.
///
/// This is intentionally a **single global** name, not per-provider.
/// It implements the "latest OAuth2 flow wins" policy: when a new flow
/// starts while another is in flight, the new flow's cookie overwrites
/// the old one.  The abandoned flow's callback then fails `csrf_checks`
/// because the cookie token no longer matches the cached token for that
/// flow's `csrf_id`.
///
/// This is a deliberate security decision: OAuth2 callbacks have
/// irreversible side effects (session rotation, account linking, login
/// history), so silently completing an abandoned parallel flow would
/// create unintended state.  Fail-closed is the correct direction.
///
/// Do NOT make this per-provider.  If a future PR proposes per-instance
/// cookie naming, it must first justify changing this policy.
/// See Decision Log entry "2026-04-16: Preserve the 'latest flow wins'
/// CSRF cookie policy" in issue `20260226-2020`.
pub(crate) static OAUTH2_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub(super) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> =
    LazyLock::new(|| match std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE") {
        Ok(val) => val.parse().unwrap_or_else(|e| {
            panic!("OAUTH2_CSRF_COOKIE_MAX_AGE='{val}' is not a valid u64: {e}")
        }),
        Err(_) => 60,
    });

/// Get the Google OAuth2 client ID.
///
/// Used by FedCM to embed the client ID in the frontend JavaScript.
/// Delegates to `GOOGLE_PROVIDER.client_id` so the value is always
/// consistent with the running provider configuration.
pub fn get_google_client_id() -> &'static str {
    &crate::oauth2::provider::GOOGLE_PROVIDER.client_id
}

#[cfg(test)]
mod tests;
