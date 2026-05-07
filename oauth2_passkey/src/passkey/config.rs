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

pub(super) static PASSKEY_TIMEOUT: LazyLock<u32> =
    LazyLock::new(|| match env::var("PASSKEY_TIMEOUT") {
        Ok(val) => val
            .parse()
            .unwrap_or_else(|e| panic!("PASSKEY_TIMEOUT='{val}' is not a valid u32: {e}")),
        Err(_) => 60,
    });

pub(super) static PASSKEY_CHALLENGE_TIMEOUT: LazyLock<u32> =
    LazyLock::new(|| match env::var("PASSKEY_CHALLENGE_TIMEOUT") {
        Ok(val) => val.parse().unwrap_or_else(|e| {
            panic!("PASSKEY_CHALLENGE_TIMEOUT='{val}' is not a valid u32: {e}")
        }),
        Err(_) => 60,
    });

pub(super) static PASSKEY_ATTESTATION: LazyLock<String> = LazyLock::new(|| {
    match env::var("PASSKEY_ATTESTATION") {
        Err(_) => "direct".to_string(),
        Ok(v) => match v.to_lowercase().as_str() {
            "none" => "none".to_string(),
            "direct" => "direct".to_string(),
            "indirect" => "indirect".to_string(),
            "enterprise" => "enterprise".to_string(),
            _ => panic!(
                "PASSKEY_ATTESTATION='{v}' is invalid. Valid values: none, direct, indirect, enterprise"
            ),
        },
    }
});

/// `None` means the field is omitted from the WebAuthn registration JSON,
/// which lets the browser accept either platform or cross-platform
/// authenticators. To restrict to a single attachment type, set the env
/// var to `platform` or `cross-platform` explicitly. Any other value
/// panics at startup.
pub(super) static PASSKEY_AUTHENTICATOR_ATTACHMENT: LazyLock<Option<String>> =
    LazyLock::new(|| match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT") {
        Err(_) => None,
        Ok(v) => match v.to_lowercase().as_str() {
            "platform" => Some("platform".to_string()),
            "cross-platform" => Some("cross-platform".to_string()),
            _ => panic!(
                "PASSKEY_AUTHENTICATOR_ATTACHMENT='{v}' is invalid. \
                 Valid values: platform, cross-platform. \
                 To allow either attachment, leave the variable unset."
            ),
        },
    });

pub(super) static PASSKEY_RESIDENT_KEY: LazyLock<String> = LazyLock::new(|| {
    match env::var("PASSKEY_RESIDENT_KEY") {
        Err(_) => "required".to_string(),
        Ok(v) => match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => panic!(
                "PASSKEY_RESIDENT_KEY='{v}' is invalid. Valid values: required, preferred, discouraged"
            ),
        },
    }
});

pub(super) static PASSKEY_REQUIRE_RESIDENT_KEY: LazyLock<bool> =
    LazyLock::new(|| match env::var("PASSKEY_REQUIRE_RESIDENT_KEY") {
        Err(_) => true,
        Ok(v) => match v.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!("PASSKEY_REQUIRE_RESIDENT_KEY='{v}' is invalid. Valid values: true, false"),
        },
    });

pub(super) static PASSKEY_USER_VERIFICATION: LazyLock<String> =
    LazyLock::new(|| match env::var("PASSKEY_USER_VERIFICATION") {
        Err(_) => "discouraged".to_string(),
        Ok(v) => match v.to_lowercase().as_str() {
            "required" => "required".to_string(),
            "preferred" => "preferred".to_string(),
            "discouraged" => "discouraged".to_string(),
            _ => panic!(
                "PASSKEY_USER_VERIFICATION='{v}' is invalid. \
                 Valid values: required, preferred, discouraged"
            ),
        },
    });

pub(super) static PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL: LazyLock<bool> = LazyLock::new(
    || match env::var("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL") {
        Err(_) => false,
        Ok(val) => match val.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => panic!(
                "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL='{val}' is invalid. \
                 Valid values: true, false"
            ),
        },
    },
);

#[cfg(test)]
mod tests;
