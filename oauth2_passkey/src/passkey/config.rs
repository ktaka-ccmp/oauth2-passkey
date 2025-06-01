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

#[cfg(test)]
mod tests {
    use std::env;

    // Helper function to set and restore environment variables
    fn with_env_var<F, T>(name: &str, value: Option<&str>, test: F) -> T
    where
        F: FnOnce() -> T,
    {
        // Note: Modifying environment variables is inherently unsafe because
        // it can affect other tests running in parallel. We use an unsafe block
        // to acknowledge this risk, but in a real-world scenario, we would use
        // a more robust approach like test isolation.
        unsafe {
            // Save the original value
            let original = env::var(name).ok();

            // Set the new value or remove it
            match value {
                Some(val) => env::set_var(name, val),
                None => env::remove_var(name),
            }

            // Run the test and get the result
            let result = test();

            // Restore the original value
            match original {
                Some(val) => env::set_var(name, val),
                None => env::remove_var(name),
            }

            result
        }
    }

    // Test helper functions that mimic the logic in the LazyLock values

    fn get_passkey_timeout() -> u32 {
        env::var("PASSKEY_TIMEOUT")
            .map(|v| v.parse::<u32>().unwrap_or(60))
            .unwrap_or(60)
    }

    fn get_passkey_attestation() -> String {
        match env::var("PASSKEY_ATTESTATION").ok() {
            None => "direct".to_string(),
            Some(v) => match v.to_lowercase().as_str() {
                "none" => "none".to_string(),
                "direct" => "direct".to_string(),
                "indirect" => "indirect".to_string(),
                "enterprise" => "enterprise".to_string(),
                _invalid => "direct".to_string(),
            },
        }
    }

    fn get_passkey_authenticator_attachment() -> String {
        match env::var("PASSKEY_AUTHENTICATOR_ATTACHMENT").ok() {
            None => "platform".to_string(),
            Some(v) => match v.to_lowercase().as_str() {
                "platform" => "platform".to_string(),
                "cross-platform" => "cross-platform".to_string(),
                "none" => "None".to_string(), // Ensure "None" is capitalized
                _invalid => "platform".to_string(),
            },
        }
    }

    fn get_passkey_resident_key() -> String {
        env::var("PASSKEY_RESIDENT_KEY").map_or(
            "required".to_string(), // Default to required
            |v| match v.to_lowercase().as_str() {
                "required" => "required".to_string(),
                "preferred" => "preferred".to_string(),
                "discouraged" => "discouraged".to_string(),
                _ => "required".to_string(),
            },
        )
    }

    fn get_passkey_require_resident_key() -> bool {
        env::var("PASSKEY_REQUIRE_RESIDENT_KEY").map_or(
            true, // Default to true
            |v| match v.to_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _invalid => true,
            },
        )
    }

    fn get_passkey_user_verification() -> String {
        env::var("PASSKEY_USER_VERIFICATION").map_or(
            "discouraged".to_string(), // Default to discouraged
            |v| match v.to_lowercase().as_str() {
                "required" => "required".to_string(),
                "preferred" => "preferred".to_string(),
                "discouraged" => "discouraged".to_string(),
                _ => "discouraged".to_string(),
            },
        )
    }

    fn get_passkey_user_handle_unique_for_every_credential() -> bool {
        env::var("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL")
            .map(|v| v.parse::<bool>().unwrap_or(true))
            .unwrap_or(true)
    }

    #[test]
    fn test_passkey_timeout_default() {
        let timeout = with_env_var("PASSKEY_TIMEOUT", None, || get_passkey_timeout());
        assert_eq!(timeout, 60, "Default timeout should be 60 seconds");
    }

    #[test]
    fn test_passkey_timeout_custom() {
        let timeout = with_env_var("PASSKEY_TIMEOUT", Some("120"), || get_passkey_timeout());
        assert_eq!(timeout, 120, "Custom timeout should be 120 seconds");
    }

    #[test]
    fn test_passkey_timeout_invalid() {
        let timeout = with_env_var("PASSKEY_TIMEOUT", Some("invalid"), || get_passkey_timeout());
        assert_eq!(timeout, 60, "Invalid timeout should default to 60 seconds");
    }

    #[test]
    fn test_passkey_attestation_default() {
        // Use the with_env_var helper to safely manage environment variables
        let attestation = with_env_var("PASSKEY_ATTESTATION", None, || get_passkey_attestation());
        assert_eq!(
            attestation, "direct",
            "Default attestation should be 'direct'"
        );
    }

    #[test]
    fn test_passkey_attestation_valid_values() {
        // Test each value separately to ensure proper isolation
        let attestation_none = with_env_var("PASSKEY_ATTESTATION", Some("none"), || {
            get_passkey_attestation()
        });
        assert_eq!(
            attestation_none, "none",
            "Attestation should match valid input 'none'"
        );

        let attestation_direct = with_env_var("PASSKEY_ATTESTATION", Some("direct"), || {
            get_passkey_attestation()
        });
        assert_eq!(
            attestation_direct, "direct",
            "Attestation should match valid input 'direct'"
        );

        let attestation_indirect = with_env_var("PASSKEY_ATTESTATION", Some("indirect"), || {
            get_passkey_attestation()
        });
        assert_eq!(
            attestation_indirect, "indirect",
            "Attestation should match valid input 'indirect'"
        );

        let attestation_enterprise =
            with_env_var("PASSKEY_ATTESTATION", Some("enterprise"), || {
                get_passkey_attestation()
            });
        assert_eq!(
            attestation_enterprise, "enterprise",
            "Attestation should match valid input 'enterprise'"
        );
    }

    #[test]
    fn test_passkey_attestation_invalid() {
        let attestation = with_env_var("PASSKEY_ATTESTATION", Some("invalid_value"), || {
            get_passkey_attestation()
        });
        assert_eq!(
            attestation, "direct",
            "Invalid attestation should default to 'direct'"
        );
    }

    #[test]
    fn test_passkey_authenticator_attachment_default() {
        let attachment = with_env_var("PASSKEY_AUTHENTICATOR_ATTACHMENT", None, || {
            get_passkey_authenticator_attachment()
        });
        assert_eq!(
            attachment, "platform",
            "Default authenticator attachment should be 'platform'"
        );
    }

    #[test]
    fn test_passkey_authenticator_attachment_valid_values() {
        // Test each value separately
        let attachment_platform =
            with_env_var("PASSKEY_AUTHENTICATOR_ATTACHMENT", Some("platform"), || {
                get_passkey_authenticator_attachment()
            });
        assert_eq!(
            attachment_platform, "platform",
            "Authenticator attachment should match valid input 'platform'"
        );

        let attachment_cross_platform = with_env_var(
            "PASSKEY_AUTHENTICATOR_ATTACHMENT",
            Some("cross-platform"),
            || get_passkey_authenticator_attachment(),
        );
        assert_eq!(
            attachment_cross_platform, "cross-platform",
            "Authenticator attachment should match valid input 'cross-platform'"
        );

        let attachment_none =
            with_env_var("PASSKEY_AUTHENTICATOR_ATTACHMENT", Some("none"), || {
                get_passkey_authenticator_attachment()
            });
        assert_eq!(
            attachment_none, "None",
            "Authenticator attachment should match valid input 'none' with capitalization"
        );
    }

    #[test]
    fn test_passkey_authenticator_attachment_invalid() {
        let attachment = with_env_var(
            "PASSKEY_AUTHENTICATOR_ATTACHMENT",
            Some("invalid_value"),
            || get_passkey_authenticator_attachment(),
        );
        assert_eq!(
            attachment, "platform",
            "Invalid authenticator attachment should default to 'platform'"
        );
    }

    #[test]
    fn test_passkey_user_verification_default() {
        let verification = with_env_var("PASSKEY_USER_VERIFICATION", None, || {
            get_passkey_user_verification()
        });
        assert_eq!(
            verification, "discouraged",
            "Default user verification should be 'discouraged'"
        );
    }

    #[test]
    fn test_passkey_user_verification_valid_values() {
        // Test each value separately
        let verification_required =
            with_env_var("PASSKEY_USER_VERIFICATION", Some("required"), || {
                get_passkey_user_verification()
            });
        assert_eq!(
            verification_required, "required",
            "User verification should match valid input 'required'"
        );

        let verification_preferred =
            with_env_var("PASSKEY_USER_VERIFICATION", Some("preferred"), || {
                get_passkey_user_verification()
            });
        assert_eq!(
            verification_preferred, "preferred",
            "User verification should match valid input 'preferred'"
        );

        let verification_discouraged =
            with_env_var("PASSKEY_USER_VERIFICATION", Some("discouraged"), || {
                get_passkey_user_verification()
            });
        assert_eq!(
            verification_discouraged, "discouraged",
            "User verification should match valid input 'discouraged'"
        );
    }

    #[test]
    fn test_passkey_user_verification_invalid() {
        let verification = with_env_var("PASSKEY_USER_VERIFICATION", Some("invalid_value"), || {
            get_passkey_user_verification()
        });
        assert_eq!(
            verification, "discouraged",
            "Invalid user verification should default to 'discouraged'"
        );
    }

    #[test]
    fn test_passkey_user_handle_unique_default() {
        let unique = with_env_var(
            "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL",
            None,
            || get_passkey_user_handle_unique_for_every_credential(),
        );
        assert!(unique, "Default user handle uniqueness should be true");
    }

    #[test]
    fn test_passkey_user_handle_unique_custom() {
        let unique = with_env_var(
            "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL",
            Some("false"),
            || get_passkey_user_handle_unique_for_every_credential(),
        );
        assert!(
            !unique,
            "User handle uniqueness should be false when set to 'false'"
        );
    }

    #[test]
    fn test_passkey_user_handle_unique_invalid() {
        let unique = with_env_var(
            "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL",
            Some("invalid"),
            || get_passkey_user_handle_unique_for_every_credential(),
        );
        assert!(
            unique,
            "Invalid user handle uniqueness should default to true"
        );
    }

    #[test]
    fn test_passkey_resident_key_default() {
        let resident_key =
            with_env_var("PASSKEY_RESIDENT_KEY", None, || get_passkey_resident_key());
        assert_eq!(
            resident_key, "required",
            "Default resident key should be 'required'"
        );
    }

    #[test]
    fn test_passkey_resident_key_valid_values() {
        // Test each value separately
        let resident_key_required = with_env_var("PASSKEY_RESIDENT_KEY", Some("required"), || {
            get_passkey_resident_key()
        });
        assert_eq!(
            resident_key_required, "required",
            "Resident key should match valid input 'required'"
        );

        let resident_key_preferred =
            with_env_var("PASSKEY_RESIDENT_KEY", Some("preferred"), || {
                get_passkey_resident_key()
            });
        assert_eq!(
            resident_key_preferred, "preferred",
            "Resident key should match valid input 'preferred'"
        );

        let resident_key_discouraged =
            with_env_var("PASSKEY_RESIDENT_KEY", Some("discouraged"), || {
                get_passkey_resident_key()
            });
        assert_eq!(
            resident_key_discouraged, "discouraged",
            "Resident key should match valid input 'discouraged'"
        );
    }

    #[test]
    fn test_passkey_resident_key_invalid() {
        let resident_key = with_env_var("PASSKEY_RESIDENT_KEY", Some("invalid_value"), || {
            get_passkey_resident_key()
        });
        assert_eq!(
            resident_key, "required",
            "Invalid resident key should default to 'required'"
        );
    }

    #[test]
    fn test_passkey_require_resident_key_default() {
        let require_resident_key = with_env_var("PASSKEY_REQUIRE_RESIDENT_KEY", None, || {
            get_passkey_require_resident_key()
        });
        assert!(
            require_resident_key,
            "Default require resident key should be true"
        );
    }

    #[test]
    fn test_passkey_require_resident_key_custom() {
        let require_resident_key =
            with_env_var("PASSKEY_REQUIRE_RESIDENT_KEY", Some("false"), || {
                get_passkey_require_resident_key()
            });
        assert!(
            !require_resident_key,
            "Require resident key should be false when set to 'false'"
        );
    }

    #[test]
    fn test_passkey_require_resident_key_invalid() {
        let require_resident_key =
            with_env_var("PASSKEY_REQUIRE_RESIDENT_KEY", Some("invalid"), || {
                get_passkey_require_resident_key()
            });
        assert!(
            require_resident_key,
            "Invalid require resident key should default to true"
        );
    }
}
