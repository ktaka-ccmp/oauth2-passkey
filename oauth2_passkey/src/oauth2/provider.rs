use std::{
    env,
    sync::{LazyLock, OnceLock},
};

use crate::config::O2P_ROUTE_PREFIX;
use crate::oauth2::discovery::{OidcDiscoveryDocument, OidcDiscoveryError, fetch_oidc_discovery};

/// URL-facing identifier of a **registered** OAuth2/OIDC provider.
///
/// Wraps a `&'static str` that is either a compile-time literal (named
/// providers, preset defaults) or a `Box::leak`-ed value produced from an
/// operator-supplied env var at `LazyLock` init (custom slots). The value
/// has been validated for shape via `is_valid_custom_provider_name` (see
/// `validate_custom_slots`) before any `ProviderName` constructed from env
/// input reaches callers.
///
/// The newtype is not a parser — it does not re-validate its input at
/// construction. It exists so function signatures can carry
/// "provider-identifier" as a distinct type from other `&str` parameters
/// (display name, client secret, etc.), letting the compiler catch
/// accidental argument swaps. Construction paths stay `pub(crate)` so the
/// invariant holds at the crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderName(&'static str);

impl ProviderName {
    /// Wrap a compile-time literal. Caller is responsible for shape
    /// (only used at authored LazyLock / preset initializers).
    pub(crate) const fn from_static(s: &'static str) -> Self {
        Self(s)
    }

    /// Leak an operator-supplied `String` (from `OAUTH2_CUSTOM{N}_NAME`)
    /// to `'static`. The leak is bounded by the number of custom slots —
    /// eight at most, each initialized at most once per process by
    /// `LazyLock`. Shape validation runs in `validate_custom_slots`
    /// against the resulting `ProviderConfig`, so the `Err` path there
    /// is the single source of "invalid provider name" diagnostics.
    pub(crate) fn from_env_leaked(raw: String) -> Self {
        Self(leak_static(raw))
    }

    /// Borrow the underlying `&'static str`.
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// Resolve a runtime string (URL path segment, DB-stored value) against
    /// the currently-enabled provider registry. Returns `Some(ProviderName)`
    /// only when the string matches an enabled provider's name, so the
    /// `ProviderName` invariant is preserved — callers can treat the result
    /// as "validated, registered identifier" without further checks.
    ///
    /// Returns `None` when the string is empty, does not match any enabled
    /// provider, or matches a named provider whose optional env vars are not
    /// configured.
    pub fn from_registered(s: &str) -> Option<Self> {
        ProviderKind::from_provider_name(s)
            .and_then(provider_for)
            .map(|cfg| cfg.provider_name)
    }
}

impl std::fmt::Display for ProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl AsRef<str> for ProviderName {
    fn as_ref(&self) -> &str {
        self.0
    }
}

/// Identifies a supported OAuth2/OIDC provider.
///
/// `Google` is the only **named** variant — it has library-side features
/// (FedCM, `access_type=online`, `hd` claim handling) that cannot be
/// expressed as a generic OIDC preset. All other providers are routed
/// through `Custom(CustomSlot)` and configured via `OAUTH2_CUSTOM{N}_*`
/// env vars, optionally pre-populated by a [`ProviderPreset`] selected
/// via `OAUTH2_CUSTOM{N}_PRESET`.
///
/// Reserved names that must never become path-segment values (they collide
/// with literal routes under `/oauth2/*`):
/// "authorized", "accounts", "fedcm", "popup_close", "oauth2.js", "select",
/// plus the named-provider segment "google". Operators using a preset
/// (`PRESET=auth0` etc.) take the preset's default name ("auth0") which is
/// allowed because no library route shadows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ProviderKind {
    Google,
    Custom(CustomSlot),
}

/// Vendor-specific defaults that pre-populate a Custom OIDC slot when the
/// operator sets `OAUTH2_CUSTOM{N}_PRESET=<key>`. Each preset provides the
/// defaults for display name, URL-facing provider name, icon, brand colors,
/// and any library-side quirks (additional allowed origins) that would
/// otherwise require a bespoke named-provider code path.
///
/// Operators can override individual fields via the usual `OAUTH2_CUSTOM{N}_*`
/// env vars; the env var wins. `additional_allowed_origins` has no env-var
/// override surface — it is a library-level invariant tied to the IdP's
/// login UI (e.g. Entra personal routes credentials through login.live.com
/// while its OIDC endpoints live on login.microsoftonline.com).
pub(crate) struct ProviderPreset {
    pub(crate) display_name: &'static str,
    pub(crate) provider_name: ProviderName,
    pub(crate) icon_slug: &'static str,
    pub(crate) button_color: &'static str,
    pub(crate) button_hover_color: &'static str,
    pub(crate) additional_allowed_origins: &'static [&'static str],
}

pub(crate) const AUTH0_PRESET: ProviderPreset = ProviderPreset {
    display_name: "Auth0",
    provider_name: ProviderName::from_static("auth0"),
    icon_slug: "auth0",
    button_color: "#eb5424",
    button_hover_color: "#c94419",
    additional_allowed_origins: &[],
};

pub(crate) const KEYCLOAK_PRESET: ProviderPreset = ProviderPreset {
    display_name: "Keycloak",
    provider_name: ProviderName::from_static("keycloak"),
    icon_slug: "keycloak",
    button_color: "#4d4d4d",
    button_hover_color: "#333333",
    additional_allowed_origins: &[],
};

pub(crate) const ENTRA_PRESET: ProviderPreset = ProviderPreset {
    display_name: "Microsoft",
    provider_name: ProviderName::from_static("entra"),
    icon_slug: "entra",
    button_color: "#0078D4",
    button_hover_color: "#005A9E",
    // Microsoft routes personal MS account (B2C / consumers tenant) login
    // through `login.live.com`; its Referer on the form_post callback is
    // that host rather than `login.microsoftonline.com`.
    additional_allowed_origins: &["https://login.live.com"],
};

/// Resolve a preset key (from `OAUTH2_CUSTOM{N}_PRESET`) to its
/// [`ProviderPreset`]. Returns `Err` with an operator-facing message on
/// unknown keys so `init()` can fail fast.
fn resolve_preset(key: &str) -> Result<&'static ProviderPreset, String> {
    match key {
        "auth0" => Ok(&AUTH0_PRESET),
        "keycloak" => Ok(&KEYCLOAK_PRESET),
        "entra" => Ok(&ENTRA_PRESET),
        other => Err(format!(
            "unknown PRESET '{other}' (expected one of: auth0, keycloak, entra)"
        )),
    }
}

/// Identifies one of the eight generic OIDC provider slots.
///
/// Each slot is independently configured via `OAUTH2_CUSTOM{N}_*` env vars.
/// A fixed-slot design was chosen over a dynamic registry to preserve
/// compile-time `match` exhaustiveness (see issue `20260420-1511`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CustomSlot {
    Slot1,
    Slot2,
    Slot3,
    Slot4,
    Slot5,
    Slot6,
    Slot7,
    Slot8,
}

impl CustomSlot {
    pub(crate) const ALL: &'static [Self] = &[
        Self::Slot1,
        Self::Slot2,
        Self::Slot3,
        Self::Slot4,
        Self::Slot5,
        Self::Slot6,
        Self::Slot7,
        Self::Slot8,
    ];

    /// Stable internal label for this slot — `"custom1".."custom8"`.
    /// Used for diagnostics; NOT the URL path segment (that comes from
    /// `OAUTH2_CUSTOM{N}_NAME` and lives on `ProviderConfig`).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Slot1 => "custom1",
            Self::Slot2 => "custom2",
            Self::Slot3 => "custom3",
            Self::Slot4 => "custom4",
            Self::Slot5 => "custom5",
            Self::Slot6 => "custom6",
            Self::Slot7 => "custom7",
            Self::Slot8 => "custom8",
        }
    }

    /// Env-var prefix for this slot — `"OAUTH2_CUSTOM1".."OAUTH2_CUSTOM8"`.
    pub(crate) const fn env_prefix(self) -> &'static str {
        match self {
            Self::Slot1 => "OAUTH2_CUSTOM1",
            Self::Slot2 => "OAUTH2_CUSTOM2",
            Self::Slot3 => "OAUTH2_CUSTOM3",
            Self::Slot4 => "OAUTH2_CUSTOM4",
            Self::Slot5 => "OAUTH2_CUSTOM5",
            Self::Slot6 => "OAUTH2_CUSTOM6",
            Self::Slot7 => "OAUTH2_CUSTOM7",
            Self::Slot8 => "OAUTH2_CUSTOM8",
        }
    }

    /// CSS button class for this slot — `"btn-oauth2 btn-custom1".."btn-custom8"`.
    /// The `.btn-custom{N}` rules are defined in `o2p-base.css` and consume
    /// the `--o2p-custom{N}` / `--o2p-custom{N}-hover` CSS variables injected
    /// by the template for enabled slots.
    pub(crate) const fn button_class(self) -> &'static str {
        match self {
            Self::Slot1 => "btn-oauth2 btn-custom1",
            Self::Slot2 => "btn-oauth2 btn-custom2",
            Self::Slot3 => "btn-oauth2 btn-custom3",
            Self::Slot4 => "btn-oauth2 btn-custom4",
            Self::Slot5 => "btn-oauth2 btn-custom5",
            Self::Slot6 => "btn-oauth2 btn-custom6",
            Self::Slot7 => "btn-oauth2 btn-custom7",
            Self::Slot8 => "btn-oauth2 btn-custom8",
        }
    }
}

impl ProviderKind {
    /// All supported provider kinds in stable display order.
    /// Google first, then the eight generic OIDC slots.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Google,
        Self::Custom(CustomSlot::Slot1),
        Self::Custom(CustomSlot::Slot2),
        Self::Custom(CustomSlot::Slot3),
        Self::Custom(CustomSlot::Slot4),
        Self::Custom(CustomSlot::Slot5),
        Self::Custom(CustomSlot::Slot6),
        Self::Custom(CustomSlot::Slot7),
        Self::Custom(CustomSlot::Slot8),
    ];

    /// Env-var validation contract for optional providers.
    ///
    /// Returns `Some((trigger, dependents))` for providers activated by one
    /// env var that require additional env vars when that trigger is set.
    /// Returns `None` for unconditional providers (validated directly in `init`).
    ///
    /// Used by `init` to fail fast at startup instead of panicking mid-request
    /// via the `LazyLock.expect()` inside the matching static.
    ///
    /// `DISPLAY_NAME` / `NAME` are intentionally NOT in the required list:
    /// when `OAUTH2_CUSTOM{N}_PRESET` is set, the preset supplies those
    /// defaults. `validate_custom_slot_preset_shape` handles the
    /// preset-aware requirement check.
    pub(crate) fn optional_env_contract(&self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Self::Google => None,
            Self::Custom(CustomSlot::Slot1) => Some((
                "OAUTH2_CUSTOM1_CLIENT_ID",
                &["OAUTH2_CUSTOM1_CLIENT_SECRET", "OAUTH2_CUSTOM1_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot2) => Some((
                "OAUTH2_CUSTOM2_CLIENT_ID",
                &["OAUTH2_CUSTOM2_CLIENT_SECRET", "OAUTH2_CUSTOM2_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot3) => Some((
                "OAUTH2_CUSTOM3_CLIENT_ID",
                &["OAUTH2_CUSTOM3_CLIENT_SECRET", "OAUTH2_CUSTOM3_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot4) => Some((
                "OAUTH2_CUSTOM4_CLIENT_ID",
                &["OAUTH2_CUSTOM4_CLIENT_SECRET", "OAUTH2_CUSTOM4_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot5) => Some((
                "OAUTH2_CUSTOM5_CLIENT_ID",
                &["OAUTH2_CUSTOM5_CLIENT_SECRET", "OAUTH2_CUSTOM5_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot6) => Some((
                "OAUTH2_CUSTOM6_CLIENT_ID",
                &["OAUTH2_CUSTOM6_CLIENT_SECRET", "OAUTH2_CUSTOM6_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot7) => Some((
                "OAUTH2_CUSTOM7_CLIENT_ID",
                &["OAUTH2_CUSTOM7_CLIENT_SECRET", "OAUTH2_CUSTOM7_ISSUER_URL"],
            )),
            Self::Custom(CustomSlot::Slot8) => Some((
                "OAUTH2_CUSTOM8_CLIENT_ID",
                &["OAUTH2_CUSTOM8_CLIENT_SECRET", "OAUTH2_CUSTOM8_ISSUER_URL"],
            )),
        }
    }

    /// Stable internal identifier. For `Custom(slot)` returns
    /// `"custom1".."custom8"` — the **slot label**, not the configurable
    /// URL path segment. Use `ProviderConfig::provider_name` when you need
    /// the URL-facing identifier.
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Custom(slot) => slot.label(),
        }
    }

    /// Parse a URL path segment (e.g. `"google"`, or a custom slot's
    /// configured segment) into a `ProviderKind`.
    ///
    /// Google is the compile-time literal; custom-slot segments are read
    /// from `ProviderConfig::provider_name` of each enabled slot.
    ///
    /// Returns `None` if the segment does not match any configured provider.
    pub(crate) fn from_provider_name(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Self::Google),
            _ => CustomSlot::ALL
                .iter()
                .copied()
                .find(|&slot| {
                    provider_for(Self::Custom(slot))
                        .is_some_and(|cfg| cfg.provider_name.as_str() == s)
                })
                .map(Self::Custom),
        }
    }
}

/// Public information about a single enabled OAuth2 provider.
///
/// Returned by [`enabled_providers`](crate::oauth2::enabled_providers). The
/// framework-integration crate (`oauth2_passkey_axum`) uses these fields to
/// render provider buttons without maintaining its own presentation table —
/// the source of truth lives on `ProviderConfig` inside this crate.
///
/// For generic OIDC slots (`Custom{1..8}`), `display_name` / `button_class` /
/// `button_color` / `button_hover_color` come from `OAUTH2_CUSTOM{N}_*` env
/// vars. For named providers they are compile-time literals.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProviderInfo {
    /// Provider identifier used in URL routing (`/oauth2/{provider_name}/`),
    /// DB rows (`oauth2_accounts.provider`), OAuth2 state (`StateParams.provider`),
    /// and templates. E.g. `"google"`, `"auth0"`, or an operator-configured
    /// value like `"my-sso"` for a custom slot.
    pub provider_name: ProviderName,
    /// Human-readable label for login buttons (e.g. `"Google"`, `"Microsoft"`).
    pub display_name: &'static str,
    /// CSS classes for the login button (e.g. `"btn-oauth2 btn-google"`).
    pub button_class: &'static str,
    /// SVG basename served under `{O2P_ROUTE_PREFIX}/icons/{icon_slug}.svg`.
    /// Named providers use their own slug; custom slots use `"openid"` (the
    /// neutral OpenID Connect mark).
    pub icon_slug: &'static str,
    /// Inline CSS `background-color` for the button. `None` for named
    /// providers (colored via `--o2p-<name>` variables in the base CSS /
    /// theme files). `Some(color)` for custom slots, injected via a
    /// `:root { --o2p-customN: ...; }` block in the login template.
    pub button_color: Option<&'static str>,
    /// Inline CSS `background-color` for the `:hover` state. `None` for
    /// named providers; `Some(color)` for custom slots.
    pub button_hover_color: Option<&'static str>,
    /// Suffix used in the `--o2p-{suffix}` / `--o2p-{suffix}-hover` CSS
    /// variables the login template injects for this provider. `None` for
    /// named providers (styled via `.btn-<name>` rules + theme variables);
    /// for custom slots this is `"custom1".."custom8"`. The framework crate
    /// uses this to build the `:root { ... }` block without re-parsing
    /// `button_class`.
    pub css_var_suffix: Option<&'static str>,
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
    /// Extra origins that `validate_origin` should accept in addition to the
    /// authorization endpoint's origin. Needed for providers whose login UI
    /// is hosted on a different host than the OIDC endpoints — notably
    /// Microsoft Entra B2C (personal MS accounts) routes credential entry
    /// through `login.live.com` while the OIDC endpoints remain on
    /// `login.microsoftonline.com`. Empty for providers where the login UI
    /// and the authorization endpoint share an origin.
    pub(crate) additional_allowed_origins: Vec<String>,
    /// URL path segment used to route `/oauth2/{segment}/*` to this provider.
    /// For named providers this equals `kind.as_str()`. For `Custom(slot)`
    /// it is the operator-supplied `OAUTH2_CUSTOM{N}_NAME`,
    /// `Box::leak`ed to `'static` at `LazyLock` init.
    pub(crate) provider_name: ProviderName,
    /// Human-readable label for login buttons (e.g. `"Google"`, `"My SSO"`).
    pub(crate) display_name: &'static str,
    /// CSS classes for the login button (e.g. `"btn-oauth2 btn-google"`).
    pub(crate) button_class: &'static str,
    /// SVG basename served under `{O2P_ROUTE_PREFIX}/icons/{slug}.svg`.
    /// Named providers use their own slug; custom slots use `"openid"`.
    pub(crate) icon_slug: &'static str,
    /// Inline CSS `background-color` value for the button. `None` for named
    /// providers (they rely on `.btn-<name>` rules + theme variables in
    /// `o2p-base.css` / `theme-*.css`). `Some(color)` for custom slots,
    /// injected via a `:root { --o2p-customN: ...; }` block in the template.
    pub(crate) button_color: Option<&'static str>,
    /// Inline CSS `background-color` for the `:hover` state of the button.
    /// `None` for named providers; `Some(color)` for custom slots.
    pub(crate) button_hover_color: Option<&'static str>,
    /// Suffix used in the `--o2p-{suffix}` / `--o2p-{suffix}-hover` CSS
    /// variables the template injects for this provider. `None` for named
    /// providers (they rely on `.btn-<name>` rules + theme variables); for
    /// custom slots this is `"custom1".."custom8"` (i.e. `CustomSlot::label`).
    pub(crate) css_var_suffix: Option<&'static str>,
    /// When `true` (default), any divergence of display-tier claims
    /// (`name`, `picture`, `family_name`, `given_name`) between the
    /// verified ID token and the `/userinfo` response is rejected.
    /// When `false`, such divergence is logged as a warning and the
    /// id_token value is used (Option B merge priority preserved).
    /// Identity-tier claims (`email`, `email_verified`,
    /// `preferred_username`, `hd`) are always hardcoded-strict; this
    /// flag does not affect them.
    pub(crate) strict_display_claims: bool,
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
    let strict_display_claims = read_strict_display_claims("OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS");
    ProviderConfig {
        kind: ProviderKind::Google,
        client_id,
        client_secret,
        issuer_url,
        redirect_uri,
        response_mode,
        query_string,
        discovery: OnceLock::new(),
        additional_allowed_origins: Vec::new(),
        provider_name: ProviderName::from_static("google"),
        display_name: "Google",
        button_class: "btn-oauth2 btn-google",
        icon_slug: "google",
        button_color: None,
        button_hover_color: None,
        css_var_suffix: None,
        strict_display_claims,
    }
});

/// Default button background color for a custom slot when
/// `OAUTH2_CUSTOM{N}_BUTTON_COLOR` is not set. Neutral gray.
const CUSTOM_DEFAULT_BUTTON_COLOR: &str = "#6b7280";

/// Default button `:hover` background color for a custom slot when
/// `OAUTH2_CUSTOM{N}_BUTTON_HOVER_COLOR` is not set. Slightly darker gray.
const CUSTOM_DEFAULT_BUTTON_HOVER_COLOR: &str = "#4b5563";

/// Leak a `String` to `&'static str`. Used at `LazyLock` init to move
/// env-var values (which are dynamic) into the `ProviderConfig` fields
/// that require `'static` lifetimes. The leak happens at most once per
/// slot per process, as `LazyLock` initializes once.
fn leak_static(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Parse an `OAUTH2_*_STRICT_DISPLAY_CLAIMS` env var. Unset or `"true"`
/// yields `Ok(true)`; `"false"` yields `Ok(false)`; any other value yields
/// `Err(message)` so callers can choose between startup-time rejection
/// (pure validator) and `LazyLock`-time panic.
fn parse_strict_display_claims(env_var: &str) -> Result<bool, String> {
    match env::var(env_var).ok().as_deref() {
        None | Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(other) => Err(format!(
            "Invalid {env_var} '{other}'. Must be 'true' or 'false'."
        )),
    }
}

/// `LazyLock`-time wrapper around `parse_strict_display_claims`. Matches the
/// on-invalid strict-parse style of `OAUTH2_RESPONSE_MODE`.
fn read_strict_display_claims(env_var: &str) -> bool {
    parse_strict_display_claims(env_var).unwrap_or_else(|msg| panic!("{msg}"))
}

/// Validate `OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS` at startup without
/// forcing `GOOGLE_PROVIDER`'s `LazyLock` to initialize.
///
/// Custom slots go through `LazyLock` init in `validate_custom_slots`, so
/// their STRICT_DISPLAY_CLAIMS gets checked there. `GOOGLE_PROVIDER` is
/// intentionally lazy so tests can override other env vars after
/// `init()`; without this function a bad value would survive startup and
/// crash the first login request instead.
pub(crate) fn validate_named_provider_strict_display_claims() -> Result<(), String> {
    parse_strict_display_claims("OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS")?;
    Ok(())
}

/// Build a `ProviderConfig` for a custom OIDC slot from its env vars.
///
/// Returns `None` if the slot's `CLIENT_ID` trigger env var is not set
/// (meaning the slot is disabled). Panics at first access if `CLIENT_ID`
/// is set but any required dependent var is missing — `init()` calls
/// `optional_env_contract` validation + `validate_custom_slot_preset_shape`
/// first, so this panic is a defense against direct static access before
/// `init()` ran.
///
/// When `OAUTH2_CUSTOM{N}_PRESET` is set (and known), the preset supplies
/// defaults for display_name / provider_name / icon_slug / button colors /
/// additional_allowed_origins. Each preset field is overridable via the
/// usual `OAUTH2_CUSTOM{N}_*` env var — env wins.
fn build_custom_provider(slot: CustomSlot) -> Option<ProviderConfig> {
    let prefix = slot.env_prefix();
    let client_id = env::var(format!("{prefix}_CLIENT_ID")).ok()?;
    let client_secret = env::var(format!("{prefix}_CLIENT_SECRET"))
        .unwrap_or_else(|_| panic!("{prefix}_CLIENT_ID set but {prefix}_CLIENT_SECRET missing"));
    let issuer_url = env::var(format!("{prefix}_ISSUER_URL"))
        .unwrap_or_else(|_| panic!("{prefix}_CLIENT_ID set but {prefix}_ISSUER_URL missing"));

    // Resolve optional preset. Invalid value → panic; matches the
    // strict-parse style used for `OAUTH2_RESPONSE_MODE`.
    let preset: Option<&'static ProviderPreset> =
        match env::var(format!("{prefix}_PRESET")).ok().as_deref() {
            None => None,
            Some(key) => {
                Some(resolve_preset(key).unwrap_or_else(|msg| panic!("{prefix}_PRESET: {msg}")))
            }
        };

    let display_name: &'static str = env::var(format!("{prefix}_DISPLAY_NAME"))
        .ok()
        .map(leak_static)
        .or(preset.map(|p| p.display_name))
        .unwrap_or_else(|| {
            panic!("{prefix}_CLIENT_ID set but {prefix}_DISPLAY_NAME missing (no PRESET to supply a default)")
        });
    let provider_name: ProviderName = env::var(format!("{prefix}_NAME"))
        .ok()
        .map(ProviderName::from_env_leaked)
        .or(preset.map(|p| p.provider_name))
        .unwrap_or_else(|| {
            panic!(
                "{prefix}_CLIENT_ID set but {prefix}_NAME missing (no PRESET to supply a default)"
            )
        });

    let origin = env::var("ORIGIN").expect("Missing ORIGIN!");

    let response_mode =
        env::var(format!("{prefix}_RESPONSE_MODE")).unwrap_or_else(|_| "form_post".to_string());
    let scope =
        env::var(format!("{prefix}_SCOPE")).unwrap_or_else(|_| "openid+email+profile".to_string());

    let button_color: &'static str = env::var(format!("{prefix}_BUTTON_COLOR"))
        .ok()
        .map(leak_static)
        .or(preset.map(|p| p.button_color))
        .unwrap_or(CUSTOM_DEFAULT_BUTTON_COLOR);
    let button_hover_color: &'static str = env::var(format!("{prefix}_BUTTON_HOVER_COLOR"))
        .ok()
        .map(leak_static)
        .or(preset.map(|p| p.button_hover_color))
        .unwrap_or(CUSTOM_DEFAULT_BUTTON_HOVER_COLOR);
    let icon_slug: &'static str = env::var(format!("{prefix}_ICON_SLUG"))
        .ok()
        .map(leak_static)
        .or(preset.map(|p| p.icon_slug))
        .unwrap_or("openid");

    let additional_allowed_origins: Vec<String> = preset
        .map(|p| {
            p.additional_allowed_origins
                .iter()
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let strict_display_claims =
        read_strict_display_claims(&format!("{prefix}_STRICT_DISPLAY_CLAIMS"));

    let redirect_uri = format!(
        "{}{}/oauth2/{}/authorized",
        origin,
        O2P_ROUTE_PREFIX.as_str(),
        provider_name
    );
    let query_string = format!(
        "&response_type=code&scope={}&response_mode={}&prompt=consent",
        scope, response_mode
    );

    Some(ProviderConfig {
        kind: ProviderKind::Custom(slot),
        client_id,
        client_secret,
        issuer_url,
        redirect_uri,
        response_mode,
        query_string,
        discovery: OnceLock::new(),
        additional_allowed_origins,
        provider_name,
        display_name,
        button_class: slot.button_class(),
        icon_slug,
        button_color: Some(button_color),
        button_hover_color: Some(button_hover_color),
        css_var_suffix: Some(slot.label()),
        strict_display_claims,
    })
}

/// Generic OIDC provider slot 1 — enabled by `OAUTH2_CUSTOM1_CLIENT_ID`.
pub(crate) static CUSTOM1_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot1));

/// Generic OIDC provider slot 2 — enabled by `OAUTH2_CUSTOM2_CLIENT_ID`.
pub(crate) static CUSTOM2_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot2));

/// Generic OIDC provider slot 3 — enabled by `OAUTH2_CUSTOM3_CLIENT_ID`.
pub(crate) static CUSTOM3_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot3));

/// Generic OIDC provider slot 4 — enabled by `OAUTH2_CUSTOM4_CLIENT_ID`.
pub(crate) static CUSTOM4_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot4));

/// Generic OIDC provider slot 5 — enabled by `OAUTH2_CUSTOM5_CLIENT_ID`.
pub(crate) static CUSTOM5_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot5));

/// Generic OIDC provider slot 6 — enabled by `OAUTH2_CUSTOM6_CLIENT_ID`.
pub(crate) static CUSTOM6_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot6));

/// Generic OIDC provider slot 7 — enabled by `OAUTH2_CUSTOM7_CLIENT_ID`.
pub(crate) static CUSTOM7_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot7));

/// Generic OIDC provider slot 8 — enabled by `OAUTH2_CUSTOM8_CLIENT_ID`.
pub(crate) static CUSTOM8_PROVIDER: LazyLock<Option<ProviderConfig>> =
    LazyLock::new(|| build_custom_provider(CustomSlot::Slot8));

/// Path segments under `/oauth2/*` that a custom-slot `NAME` must not
/// collide with: the `Google` named-provider segment plus the literal
/// routes mounted by the axum crate. `"auth0"`, `"keycloak"`, `"entra"`
/// are NOT reserved — they are the natural default names selected by
/// `OAUTH2_CUSTOM{N}_PRESET` and operators may use them directly.
pub(crate) const RESERVED_PROVIDER_NAMES: &[&str] = &[
    "google",
    "authorized",
    "accounts",
    "fedcm",
    "popup_close",
    "oauth2.js",
    "select",
];

/// Returns `true` iff `s` is non-empty and every character is in the
/// allowed path-segment alphabet (`[a-z0-9_-]+`).
fn is_valid_custom_provider_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Returns `true` iff `s` is a hex (`#rgb`, `#rgba`, `#rrggbb`, `#rrggbbaa`) or
/// a lowercase alphabetic CSS color keyword (3-30 letters). The value is
/// emitted into an inline `<style>` block, so this guard rejects syntax that
/// could break out of the CSS var declaration.
fn is_valid_css_color(s: &str) -> bool {
    match s.strip_prefix('#') {
        Some(hex) => {
            matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
        }
        None => {
            let len = s.len();
            (3..=30).contains(&len) && s.chars().all(|c| c.is_ascii_lowercase())
        }
    }
}

/// Validates value-level constraints on enabled custom OIDC slots.
///
/// Env-presence (trigger → dependents) is already covered by
/// `optional_env_contract`. This function covers the checks that operate
/// on resolved `ProviderConfig` values:
///
/// - `provider_name` matches `[a-z0-9_-]+` (non-empty)
/// - `provider_name` does not collide with named providers or reserved routes
///   (see `RESERVED_PROVIDER_NAMES`)
/// - No two enabled custom slots share the same `provider_name`
///
/// Returns an `Err` with a descriptive message on the first violation so
/// `init()` can fail fast before any request is served.
pub(crate) fn validate_custom_slots() -> Result<(), String> {
    let mut enabled_segments: Vec<(CustomSlot, ProviderName)> = Vec::new();
    for &slot in CustomSlot::ALL {
        let Some(cfg) = provider_for(ProviderKind::Custom(slot)) else {
            continue;
        };
        let seg = cfg.provider_name;

        if !is_valid_custom_provider_name(seg.as_str()) {
            return Err(format!(
                "{}_NAME='{}' is invalid: must match [a-z0-9_-]+",
                slot.env_prefix(),
                seg
            ));
        }
        if RESERVED_PROVIDER_NAMES.contains(&seg.as_str()) {
            return Err(format!(
                "{}_NAME='{}' collides with a reserved name",
                slot.env_prefix(),
                seg
            ));
        }
        if let Some((other_slot, _)) = enabled_segments.iter().find(|(_, s)| *s == seg) {
            return Err(format!(
                "{}_NAME='{}' collides with {}_NAME",
                slot.env_prefix(),
                seg,
                other_slot.env_prefix()
            ));
        }
        enabled_segments.push((slot, seg));

        if let Some(color) = cfg.button_color
            && !is_valid_css_color(color)
        {
            return Err(format!(
                "{}_BUTTON_COLOR='{}' is invalid: expected '#rgb[a]', '#rrggbb[aa]', or a CSS color keyword (3-30 lowercase letters)",
                slot.env_prefix(),
                color
            ));
        }
        if let Some(color) = cfg.button_hover_color
            && !is_valid_css_color(color)
        {
            return Err(format!(
                "{}_BUTTON_HOVER_COLOR='{}' is invalid: expected '#rgb[a]', '#rrggbb[aa]', or a CSS color keyword (3-30 lowercase letters)",
                slot.env_prefix(),
                color
            ));
        }
        // Icon slug shares the `[a-z0-9_-]+` grammar with provider_name —
        // both are URL path segments served under `/icons/{slug}.svg` and
        // `/oauth2/{name}` respectively.
        if !is_valid_custom_provider_name(cfg.icon_slug) {
            return Err(format!(
                "{}_ICON_SLUG='{}' is invalid: must match [a-z0-9_-]+",
                slot.env_prefix(),
                cfg.icon_slug
            ));
        }
    }
    Ok(())
}

/// Pre-`LazyLock` validation for the preset contract on every enabled
/// custom slot: reject invalid `OAUTH2_CUSTOM{N}_PRESET` values and, when
/// no preset is declared, require `DISPLAY_NAME` + `NAME` explicitly.
///
/// Kept separate from `validate_custom_slots` so operators get the
/// preset-shape error at startup without triggering `build_custom_provider`
/// (which panics via `unwrap_or_else` if a required field is missing).
pub(crate) fn validate_custom_slot_preset_shape() -> Result<(), String> {
    for &slot in CustomSlot::ALL {
        let prefix = slot.env_prefix();
        if env::var(format!("{prefix}_CLIENT_ID")).is_err() {
            continue;
        }
        let preset_key = env::var(format!("{prefix}_PRESET")).ok();
        let has_preset = match preset_key.as_deref() {
            None => false,
            Some(key) => {
                resolve_preset(key).map_err(|msg| format!("{prefix}_PRESET: {msg}"))?;
                true
            }
        };
        if !has_preset {
            if env::var(format!("{prefix}_DISPLAY_NAME")).is_err() {
                return Err(format!(
                    "{prefix}_CLIENT_ID is set without {prefix}_PRESET; {prefix}_DISPLAY_NAME is required"
                ));
            }
            if env::var(format!("{prefix}_NAME")).is_err() {
                return Err(format!(
                    "{prefix}_CLIENT_ID is set without {prefix}_PRESET; {prefix}_NAME is required"
                ));
            }
        }
    }
    Ok(())
}

/// Resolve a `ProviderKind` to its `&'static ProviderConfig`.
///
/// Returns `None` if the provider is optional and not configured (its env vars
/// are absent).  Google is unconditional, so this always returns `Some` for it.
pub(crate) fn provider_for(kind: ProviderKind) -> Option<&'static ProviderConfig> {
    match kind {
        ProviderKind::Google => Some(&GOOGLE_PROVIDER),
        ProviderKind::Custom(slot) => match slot {
            CustomSlot::Slot1 => CUSTOM1_PROVIDER.as_ref(),
            CustomSlot::Slot2 => CUSTOM2_PROVIDER.as_ref(),
            CustomSlot::Slot3 => CUSTOM3_PROVIDER.as_ref(),
            CustomSlot::Slot4 => CUSTOM4_PROVIDER.as_ref(),
            CustomSlot::Slot5 => CUSTOM5_PROVIDER.as_ref(),
            CustomSlot::Slot6 => CUSTOM6_PROVIDER.as_ref(),
            CustomSlot::Slot7 => CUSTOM7_PROVIDER.as_ref(),
            CustomSlot::Slot8 => CUSTOM8_PROVIDER.as_ref(),
        },
    }
}

#[cfg(test)]
mod tests;
