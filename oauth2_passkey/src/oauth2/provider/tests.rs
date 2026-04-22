use super::*;
use crate::test_utils::run_child_without_env;

// --- ProviderName ---

#[test]
fn test_provider_name_from_static_roundtrip() {
    let pn = ProviderName::from_static("google");
    assert_eq!(pn.as_str(), "google");
    assert_eq!(format!("{pn}"), "google");
    assert_eq!(AsRef::<str>::as_ref(&pn), "google");
}

#[test]
fn test_provider_name_equality_by_static_str() {
    // Same static &str contents → equal values, regardless of whether they
    // were produced by `from_static` or the const construction path inside
    // the module.
    let a = ProviderName::from_static("google");
    let b = ProviderName::from_static("google");
    let c = ProviderName::from_static("auth0");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

// `ProviderName::from_registered` forces `GOOGLE_PROVIDER` LazyLock init
// inside `ProviderKind::from_provider_name`'s custom-slot branch, so this
// test must run in a subprocess that supplies the minimum Google env vars.
#[test]
fn test_provider_name_from_registered_known() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let pn = ProviderName::from_registered("google").expect("google should resolve");
        assert_eq!(pn.as_str(), "google");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::test_provider_name_from_registered_known",
        &[
            ("OAUTH2_GOOGLE_CLIENT_ID", "id.apps.googleusercontent.com"),
            ("OAUTH2_GOOGLE_CLIENT_SECRET", "secret"),
            ("ORIGIN", "https://test.example.com"),
        ],
    );
    assert!(output.status.success(), "{output:#?}");
}

#[test]
fn test_provider_name_from_registered_unknown() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(ProviderName::from_registered("github").is_none());
        assert!(ProviderName::from_registered("").is_none());
        assert!(ProviderName::from_registered("Google").is_none()); // case-sensitive
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::test_provider_name_from_registered_unknown",
        &[
            ("OAUTH2_GOOGLE_CLIENT_ID", "id.apps.googleusercontent.com"),
            ("OAUTH2_GOOGLE_CLIENT_SECRET", "secret"),
            ("ORIGIN", "https://test.example.com"),
        ],
    );
    assert!(output.status.success(), "{output:#?}");
}

// --- ProviderKind ---

#[test]
fn test_provider_kind_from_provider_name_known() {
    assert_eq!(
        ProviderKind::from_provider_name("google"),
        Some(ProviderKind::Google)
    );
}

#[test]
fn test_provider_kind_from_provider_name_unknown() {
    assert_eq!(ProviderKind::from_provider_name("github"), None);
    assert_eq!(ProviderKind::from_provider_name(""), None);
    assert_eq!(ProviderKind::from_provider_name("Google"), None); // case-sensitive
    // Former named providers are no longer registered by default — they
    // resolve only when a Custom slot adopts that segment (via PRESET or
    // explicit `NAME=...`), which this test does not configure.
    assert_eq!(ProviderKind::from_provider_name("auth0"), None);
    assert_eq!(ProviderKind::from_provider_name("keycloak"), None);
    assert_eq!(ProviderKind::from_provider_name("entra"), None);
}

#[test]
fn test_provider_kind_as_str() {
    assert_eq!(ProviderKind::Google.as_str(), "google");
    assert_eq!(ProviderKind::Custom(CustomSlot::Slot1).as_str(), "custom1");
}

// --- optional_env_contract ---

#[test]
fn test_optional_env_contract_google() {
    assert_eq!(ProviderKind::Google.optional_env_contract(), None);
}

#[test]
fn test_optional_env_contract_custom_slot_no_longer_requires_display_name_or_name() {
    // Post-1636: DISPLAY_NAME / NAME are preset-overridable, so they are
    // NOT in the unconditional `required` list. `validate_custom_slot_preset_shape`
    // handles the preset-aware requirement check separately.
    for slot in CustomSlot::ALL {
        let (_trigger, required) = ProviderKind::Custom(*slot)
            .optional_env_contract()
            .expect("custom slots declare a contract");
        let prefix = slot.env_prefix();
        assert!(
            !required.contains(&format!("{prefix}_DISPLAY_NAME").as_str()),
            "{prefix}_DISPLAY_NAME should not be unconditionally required"
        );
        assert!(
            !required.contains(&format!("{prefix}_NAME").as_str()),
            "{prefix}_NAME should not be unconditionally required"
        );
        assert!(
            required
                .iter()
                .any(|r| *r == format!("{prefix}_CLIENT_SECRET")),
            "{prefix}_CLIENT_SECRET should still be required"
        );
        assert!(
            required
                .iter()
                .any(|r| *r == format!("{prefix}_ISSUER_URL")),
            "{prefix}_ISSUER_URL should still be required"
        );
    }
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
fn provider_kind_all_includes_google_and_custom_slots() {
    // Post-1636: only Google remains named; 8 Custom slots follow.
    assert_eq!(ProviderKind::ALL.len(), 9);
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
    // DISPLAY_NAME / NAME are preset-overridable, so not unconditional.
    assert_eq!(
        required,
        ["OAUTH2_CUSTOM1_CLIENT_SECRET", "OAUTH2_CUSTOM1_ISSUER_URL"]
    );
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
fn reserved_provider_names_cover_google_and_literal_routes() {
    // "google" stays reserved (the only named variant). "auth0", "keycloak",
    // "entra" are NOT reserved — they are the default segments supplied by
    // presets and operators may use them directly through a Custom slot.
    assert!(
        RESERVED_PROVIDER_NAMES.contains(&"google"),
        "named provider 'google' must be reserved"
    );
    for segment in ["auth0", "keycloak", "entra"] {
        assert!(
            !RESERVED_PROVIDER_NAMES.contains(&segment),
            "preset-default '{segment}' should no longer be reserved"
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
        assert_eq!(cfg.provider_name.as_str(), "my-sso");
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

// --- Named-provider STRICT_DISPLAY_CLAIMS startup validation ---
//
// Unlike Custom slots (where a bad value panics at LazyLock init via
// `validate_custom_slots`), named providers are intentionally lazy, so
// we need a pure env-value validator that runs at startup. These tests
// exercise `validate_named_provider_strict_display_claims` directly
// without touching the LazyLocks.

#[test]
fn named_provider_strict_display_claims_valid_values_accepted() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        validate_named_provider_strict_display_claims()
            .expect("valid values should pass validation");
        return;
    }
    // Only Google remains named post-1636; non-Google providers flow through
    // Custom slots (validated by `validate_custom_slots`).
    let output = run_child_with_env_set(
        "oauth2::provider::tests::named_provider_strict_display_claims_valid_values_accepted",
        &[("OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS", "true")],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn named_provider_strict_display_claims_invalid_value_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let err = validate_named_provider_strict_display_claims()
            .expect_err("invalid value must be rejected at startup");
        assert!(err.contains("OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS"));
        assert!(err.contains("'true' or 'false'"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::named_provider_strict_display_claims_invalid_value_rejected",
        &[("OAUTH2_GOOGLE_STRICT_DISPLAY_CLAIMS", "yes")],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- STRICT_DISPLAY_CLAIMS env-var tests ---

#[test]
fn custom_slot_strict_display_claims_default_true() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(cfg.strict_display_claims, "default must be true");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_strict_display_claims_default_true",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_strict_display_claims_explicit_true() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(cfg.strict_display_claims);
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_strict_display_claims_explicit_true",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS", "true"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_strict_display_claims_explicit_false() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(!cfg.strict_display_claims, "explicit false must propagate");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_strict_display_claims_explicit_false",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS", "false"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_strict_display_claims_invalid_panics() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        // LazyLock init must panic on an invalid value.
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_strict_display_claims_invalid_panics",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS", "yes"),
        ],
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OAUTH2_CUSTOM1_STRICT_DISPLAY_CLAIMS"));
    assert!(stderr.contains("'true' or 'false'"));
}

// --- Preset (OAUTH2_CUSTOM{N}_PRESET) ---

#[test]
fn custom_slot_preset_auth0_applies_defaults() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=auth0 + credentials");
        assert_eq!(cfg.provider_name.as_str(), "auth0");
        assert_eq!(cfg.display_name, "Auth0");
        assert_eq!(cfg.icon_slug, "auth0");
        assert_eq!(cfg.button_color, Some("#eb5424"));
        assert_eq!(cfg.button_hover_color, Some("#c94419"));
        assert!(cfg.additional_allowed_origins.is_empty());
        validate_custom_slots().expect("preset config should validate");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_auth0_applies_defaults",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://dev-xxx.auth0.com"),
            ("OAUTH2_CUSTOM1_PRESET", "auth0"),
            // DISPLAY_NAME and NAME omitted — preset supplies defaults.
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_keycloak_applies_defaults() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=keycloak + credentials");
        assert_eq!(cfg.provider_name.as_str(), "keycloak");
        assert_eq!(cfg.display_name, "Keycloak");
        assert_eq!(cfg.icon_slug, "keycloak");
        assert_eq!(cfg.button_color, Some("#4d4d4d"));
        assert_eq!(cfg.button_hover_color, Some("#333333"));
        assert!(cfg.additional_allowed_origins.is_empty());
        validate_custom_slots().expect("preset config should validate");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_keycloak_applies_defaults",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            (
                "OAUTH2_CUSTOM1_ISSUER_URL",
                "http://localhost:8180/realms/myrealm",
            ),
            ("OAUTH2_CUSTOM1_PRESET", "keycloak"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_zitadel_applies_defaults() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=zitadel");
        assert_eq!(cfg.provider_name.as_str(), "zitadel");
        assert_eq!(cfg.display_name, "Zitadel");
        assert_eq!(cfg.icon_slug, "zitadel");
        assert_eq!(cfg.button_color, Some("#333333"));
        assert_eq!(cfg.button_hover_color, Some("#1a1a1a"));
        assert!(cfg.additional_allowed_origins.is_empty());
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_zitadel_applies_defaults",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "http://localhost:8080"),
            ("OAUTH2_CUSTOM1_PRESET", "zitadel"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_okta_applies_defaults() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=okta");
        assert_eq!(cfg.provider_name.as_str(), "okta");
        assert_eq!(cfg.display_name, "Okta");
        assert_eq!(cfg.icon_slug, "okta");
        assert_eq!(cfg.button_color, Some("#007dc1"));
        assert_eq!(cfg.button_hover_color, Some("#005e93"));
        assert!(cfg.additional_allowed_origins.is_empty());
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_okta_applies_defaults",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            (
                "OAUTH2_CUSTOM1_ISSUER_URL",
                "https://example.okta.com/oauth2/default",
            ),
            ("OAUTH2_CUSTOM1_PRESET", "okta"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_authentik_applies_defaults() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=authentik");
        assert_eq!(cfg.provider_name.as_str(), "authentik");
        assert_eq!(cfg.display_name, "Authentik");
        assert_eq!(cfg.icon_slug, "authentik");
        assert_eq!(cfg.button_color, Some("#fd4b2d"));
        assert_eq!(cfg.button_hover_color, Some("#e03d1f"));
        assert!(cfg.additional_allowed_origins.is_empty());
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_authentik_applies_defaults",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            (
                "OAUTH2_CUSTOM1_ISSUER_URL",
                "http://localhost:9000/application/o/o2p/",
            ),
            ("OAUTH2_CUSTOM1_PRESET", "authentik"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// Policy guard: `auth0`/`keycloak`/`entra` are removed from
// RESERVED_PROVIDER_NAMES in commit 3. An operator can adopt
// `OAUTH2_CUSTOM1_NAME=auth0` WITHOUT `PRESET=auth0` — e.g. for a bare
// Custom slot that happens to be pointed at an Auth0 tenant but uses
// explicit overrides. Validates the de-reservation is honored end-to-end.
#[test]
fn custom_slot_name_auth0_without_preset_initializes() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with NAME=auth0 + no preset");
        assert_eq!(cfg.provider_name.as_str(), "auth0");
        assert_eq!(cfg.display_name, "Bare Auth0 Slot");
        // No preset → neutral-gray defaults, NOT the Auth0-branded colors.
        assert_eq!(cfg.button_color, Some(CUSTOM_DEFAULT_BUTTON_COLOR));
        assert_eq!(cfg.icon_slug, "openid");
        validate_custom_slots().expect("NAME=auth0 without preset must validate");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_name_auth0_without_preset_initializes",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://example.auth0.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "Bare Auth0 Slot"),
            ("OAUTH2_CUSTOM1_NAME", "auth0"),
            // No OAUTH2_CUSTOM1_PRESET — must still succeed.
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_entra_threads_additional_allowed_origins() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with PRESET=entra");
        assert_eq!(cfg.provider_name.as_str(), "entra");
        assert_eq!(
            cfg.additional_allowed_origins,
            vec!["https://login.live.com".to_string()]
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_entra_threads_additional_allowed_origins",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            (
                "OAUTH2_CUSTOM1_ISSUER_URL",
                "https://login.microsoftonline.com/t/v2.0",
            ),
            ("OAUTH2_CUSTOM1_PRESET", "entra"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_env_var_overrides_wins() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg = provider_for(ProviderKind::Custom(CustomSlot::Slot1))
            .expect("slot1 should be enabled with overridden preset");
        // Explicit NAME / DISPLAY_NAME / ICON_SLUG / BUTTON_COLOR win over preset.
        assert_eq!(cfg.provider_name.as_str(), "company-sso");
        assert_eq!(cfg.display_name, "Company SSO");
        assert_eq!(cfg.icon_slug, "openid");
        assert_eq!(cfg.button_color, Some("#ff0000"));
        // Not overridden — preset value kept.
        assert_eq!(cfg.button_hover_color, Some("#c94419"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_env_var_overrides_wins",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://dev-xxx.auth0.com"),
            ("OAUTH2_CUSTOM1_PRESET", "auth0"),
            ("OAUTH2_CUSTOM1_NAME", "company-sso"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "Company SSO"),
            ("OAUTH2_CUSTOM1_ICON_SLUG", "openid"),
            ("OAUTH2_CUSTOM1_BUTTON_COLOR", "#ff0000"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_preset_invalid_value_rejected_at_startup() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let err = validate_custom_slot_preset_shape()
            .expect_err("unknown preset key must be rejected pre-LazyLock");
        assert!(err.contains("OAUTH2_CUSTOM1_PRESET"));
        assert!(err.contains("unknown PRESET 'not-a-preset'"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_preset_invalid_value_rejected_at_startup",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_PRESET", "not-a-preset"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// --- OAUTH2_*_PROMPT env-var tests ---

#[test]
fn prompt_default_applied_to_google_query_string() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(
            GOOGLE_PROVIDER.query_string.contains("&prompt=consent"),
            "default must produce &prompt=consent; got: {}",
            GOOGLE_PROVIDER.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_default_applied_to_google_query_string",
        &[],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_default_applied_to_custom_query_string() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(
            cfg.query_string.contains("&prompt=consent"),
            "default must produce &prompt=consent; got: {}",
            cfg.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_default_applied_to_custom_query_string",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_custom_select_account_applied() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(
            cfg.query_string.contains("&prompt=select_account"),
            "must contain &prompt=select_account; got: {}",
            cfg.query_string
        );
        assert!(
            !cfg.query_string.contains("&prompt=consent"),
            "must not contain &prompt=consent; got: {}",
            cfg.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_custom_select_account_applied",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_PROMPT", "select_account"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_custom_login_applied() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(
            cfg.query_string.contains("&prompt=login"),
            "must contain &prompt=login; got: {}",
            cfg.query_string
        );
        assert!(
            !cfg.query_string.contains("&prompt=consent"),
            "must not contain &prompt=consent; got: {}",
            cfg.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_custom_login_applied",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_PROMPT", "login"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_empty_omits_parameter_custom() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert!(
            !cfg.query_string.contains("prompt="),
            "empty PROMPT must omit the parameter entirely; got: {}",
            cfg.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_empty_omits_parameter_custom",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_PROMPT", ""),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_empty_omits_parameter_google() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(
            !GOOGLE_PROVIDER.query_string.contains("prompt="),
            "empty OAUTH2_GOOGLE_PROMPT must omit the parameter; got: {}",
            GOOGLE_PROVIDER.query_string
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_empty_omits_parameter_google",
        &[("OAUTH2_GOOGLE_PROMPT", "")],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prompt_invalid_value_rejected_at_startup() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let err = validate_named_provider_prompt()
            .expect_err("invalid prompt value must be rejected at startup");
        assert!(err.contains("OAUTH2_GOOGLE_PROMPT"));
        assert!(err.contains("foobar"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::prompt_invalid_value_rejected_at_startup",
        &[("OAUTH2_GOOGLE_PROMPT", "foobar")],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_invalid_prompt_rejected_as_validation_error() {
    // Regression guard for the P2 review finding: invalid OAUTH2_CUSTOM{N}_PROMPT
    // must surface as a clean Err from validate_custom_slot_preset_shape(), not as
    // a panic inside the LazyLock init path that validate_custom_slots() forces.
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let err = validate_custom_slot_preset_shape()
            .expect_err("invalid PROMPT must be rejected pre-LazyLock");
        assert!(
            err.contains("OAUTH2_CUSTOM1_PROMPT"),
            "error must name the offending var; got: {err}"
        );
        assert!(
            err.contains("badprompt"),
            "error must include the bad value; got: {err}"
        );
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_invalid_prompt_rejected_as_validation_error",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_PROMPT", "badprompt"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_no_preset_requires_display_name_and_name() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let err = validate_custom_slot_preset_shape()
            .expect_err("no preset + missing NAME must be rejected");
        assert!(err.contains("OAUTH2_CUSTOM1_NAME"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_no_preset_requires_display_name_and_name",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            // PRESET unset, NAME/DISPLAY_NAME missing — must fail shape check.
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_icon_slug_override_applied() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let cfg =
            provider_for(ProviderKind::Custom(CustomSlot::Slot1)).expect("slot1 should be enabled");
        assert_eq!(cfg.icon_slug, "keycloak");
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_icon_slug_override_applied",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_ICON_SLUG", "keycloak"),
        ],
    );
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn custom_slot_icon_slug_invalid_shape_rejected() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = provider_for(ProviderKind::Custom(CustomSlot::Slot1));
        let err =
            validate_custom_slots().expect_err("icon_slug with invalid char must be rejected");
        assert!(err.contains("OAUTH2_CUSTOM1_ICON_SLUG"));
        assert!(err.contains("[a-z0-9_-]+"));
        return;
    }
    let output = run_child_with_env_set(
        "oauth2::provider::tests::custom_slot_icon_slug_invalid_shape_rejected",
        &[
            ("OAUTH2_CUSTOM1_CLIENT_ID", "id"),
            ("OAUTH2_CUSTOM1_CLIENT_SECRET", "sec"),
            ("OAUTH2_CUSTOM1_ISSUER_URL", "https://idp.example.com"),
            ("OAUTH2_CUSTOM1_DISPLAY_NAME", "X"),
            ("OAUTH2_CUSTOM1_NAME", "x"),
            ("OAUTH2_CUSTOM1_ICON_SLUG", "My/Icon"),
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
            provider_name: ProviderName::from_static("google"),
            display_name: "Google",
            button_class: "btn-oauth2 btn-google",
            icon_slug: "google",
            button_color: None,
            button_hover_color: None,
            css_var_suffix: None,
            strict_display_claims: true,
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
            provider_name: ProviderName::from_static("google"),
            display_name: "Google",
            button_class: "btn-oauth2 btn-google",
            icon_slug: "google",
            button_color: None,
            button_hover_color: None,
            css_var_suffix: None,
            strict_display_claims: true,
        }
    }
}
