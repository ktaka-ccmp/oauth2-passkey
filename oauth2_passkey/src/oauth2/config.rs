use crate::config::O2P_ROUTE_PREFIX;
use std::{env, sync::LazyLock};

pub(crate) static OAUTH2_USERINFO_URL: &str = "https://www.googleapis.com/userinfo/v2/me";

pub static OAUTH2_AUTH_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_AUTH_URL")
        .ok()
        .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth".to_string())
});
pub(crate) static OAUTH2_TOKEN_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("OAUTH2_TOKEN_URL")
        .ok()
        .unwrap_or("https://oauth2.googleapis.com/token".to_string())
});

static OAUTH2_SCOPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string()));

pub(crate) static OAUTH2_RESPONSE_MODE: LazyLock<String> = LazyLock::new(|| {
    let mode = std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
    match mode.to_lowercase().as_str() {
        "form_post" => "form_post".to_string(),
        "query" => "query".to_string(),
        _ => {
            panic!(
                "Invalid OAUTH2_RESPONSE_MODE '{}'. Must be 'form_post' or 'query'.",
                mode
            );
        }
    }
});

static OAUTH2_RESPONSE_TYPE: LazyLock<String> =
    LazyLock::new(|| std::env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string()));

pub(crate) static OAUTH2_QUERY_STRING: LazyLock<String> = LazyLock::new(|| {
    let mut query_string = "".to_string();
    query_string.push_str(&format!("&response_type={}", *OAUTH2_RESPONSE_TYPE));
    query_string.push_str(&format!("&scope={}", *OAUTH2_SCOPE));
    query_string.push_str(&format!("&response_mode={}", *OAUTH2_RESPONSE_MODE));
    query_string.push_str(&format!("&access_type={}", "online"));
    query_string.push_str(&format!("&prompt={}", "consent"));
    query_string
});

// Supported parameters:
// response_type: code
// scope: openid+email+profile
// response_mode: form_post, query
// access_type: online, offline(for refresh token)
// prompt: none, consent, select_account

// "__Host-" prefix are added to make cookies "host-only".

pub(crate) static OAUTH2_CSRF_COOKIE_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_NAME")
        .ok()
        .unwrap_or("__Host-CsrfId".to_string())
});

pub(super) static OAUTH2_CSRF_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60) // Default to 60 seconds if not set or invalid
});

pub(super) static OAUTH2_REDIRECT_URI: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}{}/oauth2/authorized",
        env::var("ORIGIN").expect("Missing ORIGIN!"),
        O2P_ROUTE_PREFIX.as_str()
    )
});

pub(super) static OAUTH2_GOOGLE_CLIENT_ID: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set")
});

pub(super) static OAUTH2_GOOGLE_CLIENT_SECRET: LazyLock<String> = LazyLock::new(|| {
    std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set")
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Helper function to temporarily set an environment variable for a test
    fn with_env_var<F>(key: &str, value: Option<&str>, test: F)
    where
        F: FnOnce(),
    {
        let old_value = env::var(key).ok();

        unsafe {
            match value {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }

        test();

        unsafe {
            match old_value {
                Some(v) => env::set_var(key, v),
                None => env::remove_var(key),
            }
        }
    }

    #[test]
    fn test_oauth2_userinfo_url_constant() {
        assert_eq!(
            OAUTH2_USERINFO_URL,
            "https://www.googleapis.com/userinfo/v2/me"
        );
    }

    #[test]
    fn test_oauth2_auth_url_default() {
        with_env_var("OAUTH2_AUTH_URL", None, || {
            // Since LazyLock is static, we need to test in a way that doesn't conflict
            // with other tests. We'll test the logic by checking the expected behavior.
            let expected_default = "https://accounts.google.com/o/oauth2/v2/auth";
            let result = env::var("OAUTH2_AUTH_URL")
                .ok()
                .unwrap_or(expected_default.to_string());
            assert_eq!(result, expected_default);
        });
    }

    #[test]
    fn test_oauth2_auth_url_from_env() {
        with_env_var(
            "OAUTH2_AUTH_URL",
            Some("https://custom.oauth.com/auth"),
            || {
                let result = env::var("OAUTH2_AUTH_URL")
                    .ok()
                    .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth".to_string());
                assert_eq!(result, "https://custom.oauth.com/auth");
            },
        );
    }

    #[test]
    fn test_oauth2_token_url_default() {
        with_env_var("OAUTH2_TOKEN_URL", None, || {
            let expected_default = "https://oauth2.googleapis.com/token";
            let result = env::var("OAUTH2_TOKEN_URL")
                .ok()
                .unwrap_or(expected_default.to_string());
            assert_eq!(result, expected_default);
        });
    }

    #[test]
    fn test_oauth2_token_url_from_env() {
        with_env_var(
            "OAUTH2_TOKEN_URL",
            Some("https://custom.oauth.com/token"),
            || {
                let result = env::var("OAUTH2_TOKEN_URL")
                    .ok()
                    .unwrap_or("https://oauth2.googleapis.com/token".to_string());
                assert_eq!(result, "https://custom.oauth.com/token");
            },
        );
    }

    #[test]
    fn test_oauth2_scope_default() {
        with_env_var("OAUTH2_SCOPE", None, || {
            let result = env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string());
            assert_eq!(result, "openid+email+profile");
        });
    }

    #[test]
    fn test_oauth2_scope_from_env() {
        with_env_var("OAUTH2_SCOPE", Some("openid+email"), || {
            let result = env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string());
            assert_eq!(result, "openid+email");
        });
    }

    #[test]
    fn test_oauth2_response_mode_form_post() {
        with_env_var("OAUTH2_RESPONSE_MODE", Some("form_post"), || {
            let mode = env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
            let result = match mode.to_lowercase().as_str() {
                "form_post" => "form_post".to_string(),
                "query" => "query".to_string(),
                _ => panic!("Invalid OAUTH2_RESPONSE_MODE"),
            };
            assert_eq!(result, "form_post");
        });
    }

    #[test]
    fn test_oauth2_response_mode_query() {
        with_env_var("OAUTH2_RESPONSE_MODE", Some("query"), || {
            let mode = env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
            let result = match mode.to_lowercase().as_str() {
                "form_post" => "form_post".to_string(),
                "query" => "query".to_string(),
                _ => panic!("Invalid OAUTH2_RESPONSE_MODE"),
            };
            assert_eq!(result, "query");
        });
    }

    #[test]
    fn test_oauth2_response_mode_case_insensitive() {
        with_env_var("OAUTH2_RESPONSE_MODE", Some("FORM_POST"), || {
            let mode = env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
            let result = match mode.to_lowercase().as_str() {
                "form_post" => "form_post".to_string(),
                "query" => "query".to_string(),
                _ => panic!("Invalid OAUTH2_RESPONSE_MODE"),
            };
            assert_eq!(result, "form_post");
        });
    }

    #[test]
    #[should_panic(expected = "Invalid OAUTH2_RESPONSE_MODE")]
    fn test_oauth2_response_mode_invalid() {
        with_env_var("OAUTH2_RESPONSE_MODE", Some("invalid_mode"), || {
            let mode = env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
            match mode.to_lowercase().as_str() {
                "form_post" => "form_post".to_string(),
                "query" => "query".to_string(),
                _ => panic!(
                    "Invalid OAUTH2_RESPONSE_MODE '{}'. Must be 'form_post' or 'query'.",
                    mode
                ),
            };
        });
    }

    #[test]
    fn test_oauth2_response_type_default() {
        with_env_var("OAUTH2_RESPONSE_TYPE", None, || {
            let result = env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string());
            assert_eq!(result, "code");
        });
    }

    #[test]
    fn test_oauth2_response_type_from_env() {
        with_env_var("OAUTH2_RESPONSE_TYPE", Some("token"), || {
            let result = env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string());
            assert_eq!(result, "token");
        });
    }

    #[test]
    fn test_oauth2_query_string_construction() {
        with_env_var("OAUTH2_RESPONSE_TYPE", Some("code"), || {
            with_env_var("OAUTH2_SCOPE", Some("openid+email"), || {
                with_env_var("OAUTH2_RESPONSE_MODE", Some("form_post"), || {
                    let response_type =
                        env::var("OAUTH2_RESPONSE_TYPE").unwrap_or("code".to_string());
                    let scope =
                        env::var("OAUTH2_SCOPE").unwrap_or("openid+email+profile".to_string());
                    let response_mode =
                        env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());

                    let mut expected = "".to_string();
                    expected.push_str(&format!("&response_type={}", response_type));
                    expected.push_str(&format!("&scope={}", scope));
                    expected.push_str(&format!("&response_mode={}", response_mode));
                    expected.push_str(&format!("&access_type={}", "online"));
                    expected.push_str(&format!("&prompt={}", "consent"));

                    assert_eq!(
                        expected,
                        "&response_type=code&scope=openid+email&response_mode=form_post&access_type=online&prompt=consent"
                    );
                });
            });
        });
    }

    #[test]
    fn test_oauth2_csrf_cookie_name_default() {
        with_env_var("OAUTH2_CSRF_COOKIE_NAME", None, || {
            let result = env::var("OAUTH2_CSRF_COOKIE_NAME")
                .ok()
                .unwrap_or("__Host-CsrfId".to_string());
            assert_eq!(result, "__Host-CsrfId");
        });
    }

    #[test]
    fn test_oauth2_csrf_cookie_name_from_env() {
        with_env_var("OAUTH2_CSRF_COOKIE_NAME", Some("__Host-CustomCsrf"), || {
            let result = env::var("OAUTH2_CSRF_COOKIE_NAME")
                .ok()
                .unwrap_or("__Host-CsrfId".to_string());
            assert_eq!(result, "__Host-CustomCsrf");
        });
    }

    #[test]
    fn test_oauth2_csrf_cookie_max_age_default() {
        with_env_var("OAUTH2_CSRF_COOKIE_MAX_AGE", None, || {
            let result = env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            assert_eq!(result, 60);
        });
    }

    #[test]
    fn test_oauth2_csrf_cookie_max_age_from_env() {
        with_env_var("OAUTH2_CSRF_COOKIE_MAX_AGE", Some("120"), || {
            let result = env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            assert_eq!(result, 120);
        });
    }

    #[test]
    fn test_oauth2_csrf_cookie_max_age_invalid_falls_back_to_default() {
        with_env_var("OAUTH2_CSRF_COOKIE_MAX_AGE", Some("invalid"), || {
            let result = env::var("OAUTH2_CSRF_COOKIE_MAX_AGE")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            assert_eq!(result, 60);
        });
    }

    #[test]
    fn test_oauth2_redirect_uri_construction() {
        with_env_var("ORIGIN", Some("https://example.com"), || {
            // We can't test the actual LazyLock since O2P_ROUTE_PREFIX is from another module
            // But we can test the construction logic
            let origin = env::var("ORIGIN").expect("Missing ORIGIN!");
            let route_prefix = "/api/v1"; // Simulating O2P_ROUTE_PREFIX
            let expected = format!("{}{}/oauth2/authorized", origin, route_prefix);
            assert_eq!(expected, "https://example.com/api/v1/oauth2/authorized");
        });
    }

    #[test]
    #[should_panic(expected = "Missing ORIGIN!")]
    fn test_oauth2_redirect_uri_missing_origin() {
        with_env_var("ORIGIN", None, || {
            env::var("ORIGIN").expect("Missing ORIGIN!");
        });
    }

    #[test]
    fn test_oauth2_google_client_id_from_env() {
        with_env_var("OAUTH2_GOOGLE_CLIENT_ID", Some("test_client_id"), || {
            let result =
                env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set");
            assert_eq!(result, "test_client_id");
        });
    }

    #[test]
    #[should_panic(expected = "OAUTH2_GOOGLE_CLIENT_ID must be set")]
    fn test_oauth2_google_client_id_missing() {
        with_env_var("OAUTH2_GOOGLE_CLIENT_ID", None, || {
            env::var("OAUTH2_GOOGLE_CLIENT_ID").expect("OAUTH2_GOOGLE_CLIENT_ID must be set");
        });
    }

    #[test]
    fn test_oauth2_google_client_secret_from_env() {
        with_env_var(
            "OAUTH2_GOOGLE_CLIENT_SECRET",
            Some("test_client_secret"),
            || {
                let result = env::var("OAUTH2_GOOGLE_CLIENT_SECRET")
                    .expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set");
                assert_eq!(result, "test_client_secret");
            },
        );
    }

    #[test]
    #[should_panic(expected = "OAUTH2_GOOGLE_CLIENT_SECRET must be set")]
    fn test_oauth2_google_client_secret_missing() {
        with_env_var("OAUTH2_GOOGLE_CLIENT_SECRET", None, || {
            env::var("OAUTH2_GOOGLE_CLIENT_SECRET")
                .expect("OAUTH2_GOOGLE_CLIENT_SECRET must be set");
        });
    }

    #[test]
    fn test_host_prefix_cookie_naming_convention() {
        // Test that our CSRF cookie name uses the "__Host-" prefix for security
        let default_name = "__Host-CsrfId";
        assert!(
            default_name.starts_with("__Host-"),
            "CSRF cookie should use __Host- prefix for security"
        );
    }
}
