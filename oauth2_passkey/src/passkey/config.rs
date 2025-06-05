use std::{env, sync::LazyLock};

pub(super) static ORIGIN: LazyLock<String> =
    LazyLock::new(|| std::env::var("ORIGIN").expect("ORIGIN must be set"));

pub(super) static PASSKEY_RP_ID: LazyLock<String> = LazyLock::new(|| {
    ORIGIN
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .map(|s| s.to_string())
        .expect("Could not extract RP ID from ORIGIN")
});

pub(super) static PASSKEY_RP_NAME: LazyLock<String> =
    LazyLock::new(|| env::var("PASSKEY_RP_NAME").ok().unwrap_or(ORIGIN.clone()));

pub(super) static PASSKEY_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(super) static PASSKEY_CHALLENGE_TIMEOUT: LazyLock<u32> = LazyLock::new(|| {
    env::var("PASSKEY_CHALLENGE_TIMEOUT")
        .map(|v| v.parse::<u32>().unwrap_or(60))
        .unwrap_or(60)
});

pub(super) static PASSKEY_ATTESTATION: LazyLock<String> =
    LazyLock::new(|| match env::var("PASSKEY_ATTESTATION").ok() {
        None => "direct".to_string(),
        Some(v) => match v.to_lowercase().as_str() {
            "none" => "none".to_string(),
            "direct" => "direct".to_string(),
            "indirect" => "indirect".to_string(),
            "enterprise" => "enterprise".to_string(),
            invalid => {
                tracing::warn!("Invalid attestation: {}. Using default 'direct'", invalid);
                "direct".to_string()
            }
        },
    });

pub(super) static PASSKEY_AUTHENTICATOR_ATTACHMENT: LazyLock<String> = LazyLock::new(|| {
    match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").ok() {
        None => "platform".to_string(),
        Some(v) => match v.to_lowercase().as_str() {
            "platform" => "platform".to_string(),
            "cross-platform" => "cross-platform".to_string(),
            "none" => "None".to_string(), // Ensure "None" is capitalized
            invalid => {
                tracing::warn!(
                    "Invalid authenticator attachment: {}. Using default 'platform'",
                    invalid
                );
                "platform".to_string()
            }
        },
    }
});

pub(super) static PASSKEY_RESIDENT_KEY: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_RESIDENT_KEY").map_or(
        "required".to_string(), // Default to required
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!("Invalid user verification: {}. Using default 'required'", v);
                "required".to_string()
            }
        },
    )
});

pub(super) static PASSKEY_REQUIRE_RESIDENT_KEY: LazyLock<bool> = LazyLock::new(|| {
    env::var("PASSKEY_REQUIRE_RESIDENT_KEY").map_or(
        true, // Default to true
        |v| match v.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            invalid => {
                tracing::warn!(
                    "Invalid require_resident_key: {}. Using default 'true'",
                    invalid
                );
                true
            }
        },
    )
});

pub(super) static PASSKEY_USER_VERIFICATION: LazyLock<String> = LazyLock::new(|| {
    env::var("PASSKEY_USER_VERIFICATION").map_or(
        "discouraged".to_string(), // Default to discouraged
        |v| match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => {
                tracing::warn!(
                    "Invalid user verification: {}. Using default 'discouraged'",
                    v
                );
                "discouraged".to_string()
            }
        },
    )
});

pub(super) static PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL: LazyLock<bool> =
    LazyLock::new(|| {
        env::var("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(true)
    });
