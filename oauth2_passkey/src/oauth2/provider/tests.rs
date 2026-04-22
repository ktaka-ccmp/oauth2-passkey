use super::*;
use crate::test_utils::run_child_without_env;

// --- ProviderKind ---

#[test]
fn test_provider_kind_from_provider_name_known() {
    assert_eq!(
        ProviderKind::from_provider_name("google"),
        Some(ProviderKind::Google)
    );
}

#[test]
fn test_provider_kind_from_provider_name_keycloak() {
    assert_eq!(
        ProviderKind::from_provider_name("keycloak"),
        Some(ProviderKind::Keycloak)
    );
}

#[test]
fn test_provider_kind_from_provider_name_unknown() {
    assert_eq!(ProviderKind::from_provider_name("github"), None);
    assert_eq!(ProviderKind::from_provider_name(""), None);
    assert_eq!(ProviderKind::from_provider_name("Google"), None); // case-sensitive
}

#[test]
fn test_provider_kind_as_str() {
    assert_eq!(ProviderKind::Google.as_str(), "google");
}

// --- from_provider_name: entra ---

#[test]
fn test_provider_kind_from_provider_name_entra() {
    assert_eq!(
        ProviderKind::from_provider_name("entra"),
        Some(ProviderKind::Entra)
    );
}

// --- optional_env_contract ---

#[test]
fn test_optional_env_contract_google() {
    assert_eq!(ProviderKind::Google.optional_env_contract(), None);
}

#[test]
fn test_optional_env_contract_auth0() {
    let (trigger, required) = ProviderKind::Auth0.optional_env_contract().unwrap();
    assert_eq!(trigger, "OAUTH2_AUTH0_CLIENT_ID");
    assert_eq!(
        required,
        ["OAUTH2_AUTH0_CLIENT_SECRET", "OAUTH2_AUTH0_ISSUER_URL"]
    );
}

#[test]
fn test_optional_env_contract_keycloak() {
    let (trigger, required) = ProviderKind::Keycloak.optional_env_contract().unwrap();
    assert_eq!(trigger, "OAUTH2_KEYCLOAK_CLIENT_ID");
    assert_eq!(
        required,
        [
            "OAUTH2_KEYCLOAK_CLIENT_SECRET",
            "OAUTH2_KEYCLOAK_ISSUER_URL"
        ]
    );
}

#[test]
fn test_optional_env_contract_entra() {
    let (trigger, required) = ProviderKind::Entra.optional_env_contract().unwrap();
    assert_eq!(trigger, "OAUTH2_ENTRA_CLIENT_ID");
    assert_eq!(
        required,
        ["OAUTH2_ENTRA_CLIENT_SECRET", "OAUTH2_ENTRA_ISSUER_URL"]
    );
}

// --- provider_for ---

#[test]
fn test_provider_for_unknown_returns_none() {
    // provider_for can only be called with ProviderKind variants;
    // there is no way to pass an unknown kind at compile time.
    // This test documents that Google resolves to Some (when env vars set)
    // and that the function signature guarantees exhaustiveness.
    // provider_for(Google) tested in test_google_provider_initialization below.
    let _ = provider_for; // just ensure it compiles and is accessible
}

// --- GOOGLE_PROVIDER initialization ---

#[test]
fn test_google_provider_init_requires_client_id() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*GOOGLE_PROVIDER;
        return;
    }
    // Should panic when OAUTH2_GOOGLE_CLIENT_ID is missing
    let output = run_child_without_env(
        "oauth2::provider::tests::test_google_provider_init_requires_client_id",
        "OAUTH2_GOOGLE_CLIENT_ID",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OAUTH2_GOOGLE_CLIENT_ID"));
}

#[test]
fn test_google_provider_init_accepts_valid_env() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(GOOGLE_PROVIDER.client_id, "test-client-id");
        assert_eq!(GOOGLE_PROVIDER.kind, ProviderKind::Google);
        assert_eq!(
            provider_for(ProviderKind::Google).map(|p| p.kind),
            Some(ProviderKind::Google)
        );
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(&exe)
        .args([
            "oauth2::provider::tests::test_google_provider_init_accepts_valid_env",
            "--exact",
            "--nocapture",
        ])
        .env("__TEST_ENV_VAR_CHILD", "1")
        .env("OAUTH2_GOOGLE_CLIENT_ID", "test-client-id")
        .env("OAUTH2_GOOGLE_CLIENT_SECRET", "test-secret")
        .env("ORIGIN", "https://example.com")
        .output()
        .expect("failed to run child process");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- CustomSlot unit tests ---

#[test]
fn custom_slot_all_has_eight_entries() {
    assert_eq!(CustomSlot::ALL.len(), 8);
    assert_eq!(CustomSlot::ALL[0], CustomSlot::Slot1);
    assert_eq!(CustomSlot::ALL[7], CustomSlot::Slot8);
}

#[test]
fn custom_slot_labels() {
    assert_eq!(CustomSlot::Slot1.label(), "custom1");
    assert_eq!(CustomSlot::Slot2.label(), "custom2");
    assert_eq!(CustomSlot::Slot3.label(), "custom3");
    assert_eq!(CustomSlot::Slot4.label(), "custom4");
    assert_eq!(CustomSlot::Slot5.label(), "custom5");
    assert_eq!(CustomSlot::Slot6.label(), "custom6");
    assert_eq!(CustomSlot::Slot7.label(), "custom7");
    assert_eq!(CustomSlot::Slot8.label(), "custom8");
}

#[test]
fn custom_slot_env_prefixes() {
    assert_eq!(CustomSlot::Slot1.env_prefix(), "OAUTH2_CUSTOM1");
    assert_eq!(CustomSlot::Slot8.env_prefix(), "OAUTH2_CUSTOM8");
}

#[test]
fn custom_slot_button_classes() {
    assert_eq!(CustomSlot::Slot1.button_class(), "btn-oauth2 btn-custom1");
    assert_eq!(CustomSlot::Slot2.button_class(), "btn-oauth2 btn-custom2");
    assert_eq!(CustomSlot::Slot3.button_class(), "btn-oauth2 btn-custom3");
    assert_eq!(CustomSlot::Slot4.button_class(), "btn-oauth2 btn-custom4");
}

#[test]
fn provider_kind_all_includes_named_and_custom() {
    assert_eq!(ProviderKind::ALL.len(), 12);
    assert!(ProviderKind::ALL.contains(&ProviderKind::Google));
    assert!(ProviderKind::ALL.contains(&ProviderKind::Custom(CustomSlot::Slot1)));
    assert!(ProviderKind::ALL.contains(&ProviderKind::Custom(CustomSlot::Slot8)));
}

#[test]
fn custom_slot_optional_env_contract_slot1() {
    let (trigger, required) = ProviderKind::Custom(CustomSlot::Slot1)
        .optional_env_contract()
        .unwrap();
    assert_eq!(trigger, "OAUTH2_CUSTOM1_CLIENT_ID");
    assert_eq!(
        required,
        [
            "OAUTH2_CUSTOM1_CLIENT_SECRET",
            "OAUTH2_CUSTOM1_ISSUER_URL",
            "OAUTH2_CUSTOM1_DISPLAY_NAME",
            "OAUTH2_CUSTOM1_NAME",
        ]
    );
}

#[test]
fn custom_slot_optional_env_contract_slot4() {
    let (trigger, required) = ProviderKind::Custom(CustomSlot::Slot4)
        .optional_env_contract()
        .unwrap();
    assert_eq!(trigger, "OAUTH2_CUSTOM4_CLIENT_ID");
    assert_eq!(required.len(), 4);
    assert!(required.contains(&"OAUTH2_CUSTOM4_DISPLAY_NAME"));
    assert!(required.contains(&"OAUTH2_CUSTOM4_NAME"));
}

#[test]
fn custom_slot_as_str_returns_label() {
    assert_eq!(ProviderKind::Custom(CustomSlot::Slot1).as_str(), "custom1");
    assert_eq!(ProviderKind::Custom(CustomSlot::Slot4).as_str(), "custom4");
}

#[test]
fn is_valid_custom_provider_name_accepts_valid() {
    assert!(is_valid_custom_provider_name("okta"));
    assert!(is_valid_custom_provider_name("my-sso"));
    assert!(is_valid_custom_provider_name("my_sso"));
    assert!(is_valid_custom_provider_name("sso1"));
    assert!(is_valid_custom_provider_name("a"));
}

#[test]
fn is_valid_custom_provider_name_rejects_invalid() {
    assert!(!is_valid_custom_provider_name(""));
    assert!(!is_valid_custom_provider_name("My-SSO")); // uppercase
    assert!(!is_valid_custom_provider_name("my/sso")); // slash
    assert!(!is_valid_custom_provider_name("my sso")); // space
    assert!(!is_valid_custom_provider_name("my.sso")); // dot
}

#[test]
fn is_valid_css_color_accepts_valid() {
    assert!(is_valid_css_color("#abc")); // 3-digit hex
    assert!(is_valid_css_color("#abcd")); // 4-digit hex (with alpha)
    assert!(is_valid_css_color("#aabbcc")); // 6-digit hex
    assert!(is_valid_css_color("#aabbccdd")); // 8-digit hex (with alpha)
    assert!(is_valid_css_color("#6B7280")); // mixed case hex
    assert!(is_valid_css_color("red")); // 3-letter keyword
    assert!(is_valid_css_color("tomato"));
    assert!(is_valid_css_color("lightgoldenrodyellow")); // 20-letter keyword
}

#[test]
fn is_valid_css_color_rejects_invalid() {
    assert!(!is_valid_css_color("")); // empty
    assert!(!is_valid_css_color("#")); // hex prefix only
    assert!(!is_valid_css_color("#ab")); // too short
    assert!(!is_valid_css_color("#abcde")); // 5-digit hex (not a valid CSS form)
    assert!(!is_valid_css_color("#abcdefg")); // 7-digit hex
    assert!(!is_valid_css_color("#abcdefghi")); // too long
    assert!(!is_valid_css_color("#xyzxyz")); // non-hex chars
    assert!(!is_valid_css_color("Red")); // uppercase keyword
    assert!(!is_valid_css_color("red ")); // trailing space
    assert!(!is_valid_css_color("rgb(0,0,0)")); // function form not supported
    assert!(!is_valid_css_color("red; } body { display:none;")); // CSS injection attempt
}

#[test]
fn reserved_provider_names_cover_named_providers_and_literal_routes() {
    for segment in ["google", "auth0", "keycloak", "entra"] {
        assert!(
            RESERVED_PROVIDER_NAMES.contains(&segment),
            "named provider '{segment}' must be reserved"
        );
    }
    for segment in [
        "authorized",
        "accounts",
        "fedcm",
        "popup_close",
        "oauth2.js",
        "select",
    ] {
        assert!(
            RESERVED_PROVIDER_NAMES.contains(&segment),
            "literal route '{segment}' must be reserved"
        );
    }
}

// --- Custom slot subprocess tests ---
//
// These launch the current test binary as a child with controlled env vars so
// the CUSTOM{N}_PROVIDER LazyLocks initialize cleanly. They verify LazyLock
// panic behavior and `validate_custom_slots` outcomes.

/// Run this test binary as a child, with a set of custom env vars applied on
/// top of the current environment. Caller must pass test name in full path
/// form (e.g. `oauth2::provider::tests::<fn_name>`).
fn run_child_with_env_set(test_name: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.args([test_name, "--exact", "--nocapture"])
        .env("__TEST_ENV_VAR_CHILD", "1")
        .env("OAUTH2_GOOGLE_CLIENT_ID", "test-client-id")
        .env("OAUTH2_GOOGLE_CLIENT_SECRET", "test-secret")
        .env("ORIGIN", "https://example.com");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run child process")
}

#[test]
fn custom_slot_missing_client_secret_panics_on_access() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        // Child: trigger set, secret missing — LazyLock access panics.
        let _ = &*CUSTOM1_PROVIDER;
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_missing_client_secret_panics_on_access",
        &[("OAUTH2_CUSTOM1_CLIENT_ID", "id")],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OAUTH2_CUSTOM1_CLIENT_SECRET"));
}

#[test]
fn custom_slot_valid_config_initializes() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with full env");
        assert_eq!(cfg.client_id, "id");
        assert_eq!(cfg.display_name, "My SSO");
        assert_eq!(cfg.provider_name, "my-sso");
        assert_eq!(cfg.icon_slug, "openid");
        assert_eq!(cfg.button_class, "btn-oauth2 btn-custom1");
        // Defaults applied
        assert_eq!(cfg.response_mode, "form_post");
        assert_eq!(cfg.button_color, Some("#6b7280"));
        assert_eq!(cfg.button_hover_color, Some("#4b5563"));
        // from_provider_name should resolve the operator-configured segment
        assert_eq!(
            ProviderKind::from_provider_name("my-sso"),
            Some(ProviderKind::Custom(CustomSlot::Slot1))
        );
        // validate_custom_slots should pass
        validate_custom_slots().expect("valid config should pass validation");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_valid_config_initializes",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "My SSO"),
            ("OAUTH2_CUSTOM1_NAME", "my-sso"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_invalid_provider_name_fails_validation() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        // Force LazyLock init to populate provider_name with the bad value.
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err = validate_custom_slots().expect_err("invalid path segment must be rejected");
        assert!(err.contains("OAUTH2_CUSTOM1_NAME"));
        assert!(err.contains("[a-z0-9_-]+"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_invalid_provider_name_fails_validation",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "My/SSO"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_reserved_provider_name_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err = validate_custom_slots().expect_err("reserved segment must be rejected");
        assert!(err.contains("reserved"));
        assert!(err.contains("authorized"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_reserved_provider_name_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "authorized"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_named_provider_collision_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err = validate_custom_slots().expect_err("collision with named provider");
        assert!(err.contains("reserved"));
        assert!(err.contains("google"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_named_provider_collision_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "google"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_duplicate_provider_name_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        // Initialize both slots' LazyLocks.
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot2));
        let err = validate_custom_slots().expect_err("duplicate segment across slots");
        assert!(err.contains("OAUTH2_CUSTOM2_NAME"));
        assert!(err.contains("OAUTH2_CUSTOM1_NAME"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_duplicate_provider_name_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id1"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec1"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp1.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "IdP One"),
            ("OAUTH2_CUSTOM1_NAME", "shared"),
            ("OAUTH2_CUSTOM2_CLIENT_ID", "id2"),
            ("OAUTH2_CUSTOM2_CLIENT_SECRET", "sec2"),
            ("OAUTH2_CUSTOM2_ISSUER_URL", "https://idp2.example.com"),
            ("OAUTH2_CUSTOM2_DISPLAY_NAME", "IdP Two"),
            ("OAUTH2_CUSTOM2_NAME", "shared"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_invalid_button_color_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err = validate_custom_slots().expect_err("bad button color must be rejected");
        assert!(err.contains("OAUTH2_CUSTOM1_BUTTON_COLOR"));
        assert!(err.contains("invalid"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_invalid_button_color_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            // CSS-break-out attempt — must not reach the inline <style> block.
            ("OAUTH2_CUSTOM1_BUTTON_COLOR", "red; } body { display:none;"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_invalid_button_hover_color_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err = validate_custom_slots().expect_err("bad hover color must be rejected");
        assert!(err.contains("OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR"));
        assert!(err.contains("invalid"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_invalid_button_hover_color_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR", "rgb(0,0,0)"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_custom_button_colors_applied() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert_eq!(cfg.button_color, Some("#ff0000"));
        assert_eq!(cfg.button_hover_color, Some("#cc0000"));
        assert_eq!(cfg.response_mode, "query");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_custom_button_colors_applied",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_BUTTON_COLOR", "#ff0000"),
            ("OAUTH2_CUSTOM1_BUTTON_HOVER_COLOR", "#cc0000"),
            ("OAUTH2_CUSTOM1_RESPONSE_MODE", "query"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl ProviderConfig {
    /// Build a `ProviderConfig` pointing at a local mock server.
    ///
    /// All discovery endpoints are pre-populated to `{base_url}/<path>` so no
    /// network calls are made and the mock server does not need to serve
    /// `/.well-known/openid-configuration`.
    ///
    /// `client_id` matches the `aud` claim emitted by `create_mock_jwt` in tests.
    pub(crate) fn for_mock_server(base_url: &str) -> Self {
        let discovery = OnceLock::new();
        let _ = discovery.set(OidcDiscoveryDocument {
            issuer: base_url.to_string(),
            authorization_endpoint: format!("{base_url}/oauth2/auth"),
            token_endpoint: format!("{base_url}/oauth2/token"),
            userinfo_endpoint: format!("{base_url}/oauth2/userinfo"),
            jwks_uri: format!("{base_url}/oauth2/v3/certs"),
            scopes_supported: None,
            response_types_supported: None,
            grant_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
        });
        let response_mode = "query";
        let query_string = format!(
            "&response_type=code&scope=openid+email+profile&response_mode={response_mode}&access_type=online&prompt=consent"
        );
        Self {
            kind: ProviderKind::Google,
            client_id: "test-client-id.apps.googleusercontent.com".to_string(),
            client_secret: "test_secret".to_string(),
            issuer_url: base_url.to_string(),
            redirect_uri: format!("{base_url}/oauth2/google/authorized"),
            response_mode: response_mode.to_string(),
            query_string,
            discovery,
            additional_allowed_origins: Vec::new(),
            provider_name: "google",
            display_name: "Google",
            button_class: "btn-oauth2 btn-google",
            icon_slug: "google",
            button_color: None,
            button_hover_color: None,
            css_var_suffix: None,
        }
    }

    /// Build a `ProviderConfig` for use in tests, with a pre-populated discovery
    /// document so no network calls are made.
    pub(crate) fn for_test(auth_url: &str, response_mode: &str) -> Self {
        let discovery = OnceLock::new();
        let _ = discovery.set(OidcDiscoveryDocument {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: auth_url.to_string(),
            token_endpoint: "https://test.example.com/token".to_string(),
            userinfo_endpoint: "https://test.example.com/userinfo".to_string(),
            jwks_uri: "https://test.example.com/.well-known/certs".to_string(),
            scopes_supported: None,
            response_types_supported: None,
            grant_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
        });
        let query_string = format!(
            "&response_type=code&scope=openid+email+profile&response_mode={}&access_type=online&prompt=consent",
            response_mode
        );
        Self {
            kind: ProviderKind::Google,
            client_id: "test_client_id".to_string(),
            client_secret: "test_secret".to_string(),
            issuer_url: "https://accounts.google.com".to_string(),
            redirect_uri: "https://test.example.com/oauth2/google/authorized".to_string(),
            response_mode: response_mode.to_string(),
            query_string,
            discovery,
            additional_allowed_origins: Vec::new(),
            provider_name: "google",
            display_name: "Google",
            button_class: "btn-oauth2 btn-google",
            icon_slug: "google",
            button_color: None,
            button_hover_color: None,
            css_var_suffix: None,
        }
    }
}
