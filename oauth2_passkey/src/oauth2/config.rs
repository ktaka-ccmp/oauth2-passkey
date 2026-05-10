use std::sync::LazyLock;

use crate::oauth2::provider::{GOOGLE_PROVIDER, ProviderInfo, ProviderKind, provider_for};

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
    &GOOGLE_PROVIDER.client_id
}

/// Returns true if the named OAuth2 provider is configured and enabled.
///
/// `name` is the URL path segment identifying the provider (e.g. `"google"`,
/// `"auth0"`). Unknown names return `false`.
pub fn is_provider_enabled(name: &str) -> bool {
    ProviderKind::from_provider_name(name)
        .and_then(provider_for)
        .is_some()
}

/// Returns [`ProviderInfo`] for the currently enabled provider whose URL
/// path segment matches `name`. Returns `None` if no such provider is
/// enabled (either the name is unknown or the provider's env vars are not
/// configured).
///
/// Use this to map a runtime provider slug (e.g. from a DB row or URL
/// segment) back to its display metadata without allocating a full
/// [`enabled_providers`] vector.
pub fn provider_info(name: &str) -> Option<ProviderInfo> {
    ProviderKind::from_provider_name(name)
        .and_then(provider_for)
        .map(|cfg| ProviderInfo {
            provider_name: cfg.provider_name,
            display_name: cfg.display_name,
            button_class: cfg.button_class,
            icon_slug: cfg.icon_slug,
            button_color: cfg.button_color,
            button_hover_color: cfg.button_hover_color,
            css_var_suffix: cfg.css_var_suffix,
        })
}

/// Returns UI info for every currently enabled OAuth2 provider, in stable
/// display order (Google first, then enabled generic OIDC slots
/// Custom1..Custom8 in order).
pub fn enabled_providers() -> Vec<ProviderInfo> {
    ProviderKind::ALL
        .iter()
        .filter_map(|&kind| {
            provider_for(kind).map(|cfg| ProviderInfo {
                provider_name: cfg.provider_name,
                display_name: cfg.display_name,
                button_class: cfg.button_class,
                icon_slug: cfg.icon_slug,
                button_color: cfg.button_color,
                button_hover_color: cfg.button_hover_color,
                css_var_suffix: cfg.css_var_suffix,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
