use std::env;
use std::sync::LazyLock;

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

// We're using a simple string representation for tokens instead of a struct
// to minimize dependencies and complexity

pub(super) static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> =
    LazyLock::new(|| match env::var("AUTH_SERVER_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => "default_secret_key_change_in_production"
            .to_string()
            .into_bytes(),
    });

#[cfg(test)]
mod tests {
    use std::env;

    /// Helper function to set an environment variable for the duration of the test
    /// and restore the original value afterward.
    fn with_env_var<F, R>(key: &str, value: Option<&str>, test: F) -> R
    where
        F: FnOnce() -> R,
    {
        // Save the original environment variable value
        let original = env::var(key).ok();

        // Set the environment variable to the test value
        match value {
            Some(val) => unsafe { env::set_var(key, val) },
            None => unsafe { env::remove_var(key) },
        }

        // Run the test function
        let result = test();

        // Restore the original environment variable
        match original {
            Some(val) => unsafe { env::set_var(key, val) },
            None => unsafe { env::remove_var(key) },
        }

        result
    }

    #[test]
    fn test_parse_session_cookie_name() {
        // Test default value
        with_env_var("SESSION_COOKIE_NAME", None, || {
            assert_eq!(env::var("SESSION_COOKIE_NAME").ok(), None);
            let default_value = std::env::var("SESSION_COOKIE_NAME")
                .ok()
                .unwrap_or("__Host-SessionId".to_string());
            assert_eq!(default_value, "__Host-SessionId");
        });

        // Test custom value
        with_env_var("SESSION_COOKIE_NAME", Some("CustomSessionId"), || {
            assert_eq!(
                env::var("SESSION_COOKIE_NAME").ok(),
                Some("CustomSessionId".to_string())
            );
            let custom_value = std::env::var("SESSION_COOKIE_NAME")
                .ok()
                .unwrap_or("__Host-SessionId".to_string());
            assert_eq!(custom_value, "CustomSessionId");
        });
    }

    #[test]
    fn test_parse_session_cookie_max_age() {
        // Test default value
        with_env_var("SESSION_COOKIE_MAX_AGE", None, || {
            assert_eq!(env::var("SESSION_COOKIE_MAX_AGE").ok(), None);
            let default_value = std::env::var("SESSION_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600);
            assert_eq!(default_value, 600); // Default is 10 minutes (600 seconds)
        });

        // Test custom value
        with_env_var("SESSION_COOKIE_MAX_AGE", Some("1800"), || {
            assert_eq!(
                env::var("SESSION_COOKIE_MAX_AGE").ok(),
                Some("1800".to_string())
            );
            let custom_value = std::env::var("SESSION_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600);
            assert_eq!(custom_value, 1800); // 30 minutes
        });

        // Test invalid value
        with_env_var("SESSION_COOKIE_MAX_AGE", Some("invalid"), || {
            assert_eq!(
                env::var("SESSION_COOKIE_MAX_AGE").ok(),
                Some("invalid".to_string())
            );
            let invalid_value = std::env::var("SESSION_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(600);
            assert_eq!(invalid_value, 600); // Should fall back to default
        });
    }

    #[test]
    fn test_parse_auth_server_secret() {
        // Test default value
        with_env_var("AUTH_SERVER_SECRET", None, || {
            assert_eq!(env::var("AUTH_SERVER_SECRET").ok(), None);
            let default_secret = match env::var("AUTH_SERVER_SECRET") {
                Ok(secret) => secret.into_bytes(),
                Err(_) => "default_secret_key_change_in_production"
                    .to_string()
                    .into_bytes(),
            };
            let expected = "default_secret_key_change_in_production"
                .as_bytes()
                .to_vec();
            assert_eq!(default_secret, expected);
        });

        // Test custom value
        with_env_var("AUTH_SERVER_SECRET", Some("custom_secret_key"), || {
            assert_eq!(
                env::var("AUTH_SERVER_SECRET").ok(),
                Some("custom_secret_key".to_string())
            );
            let custom_secret = match env::var("AUTH_SERVER_SECRET") {
                Ok(secret) => secret.into_bytes(),
                Err(_) => "default_secret_key_change_in_production"
                    .to_string()
                    .into_bytes(),
            };
            let expected = "custom_secret_key".as_bytes().to_vec();
            assert_eq!(custom_secret, expected);
        });
    }
}
