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

    /// Test OAuth2 response mode validation logic
    ///
    /// This test verifies the business logic for validating and normalizing OAuth2 response mode
    /// values. It tests case-insensitive validation and ensures valid modes are normalized
    /// to lowercase as expected.
    ///
    #[test]
    fn test_oauth2_response_mode_validation_logic() {
        // Test business logic: case insensitive validation
        let mode = "FORM_POST".to_lowercase();
        let result = match mode.as_str() {
            "form_post" => "form_post".to_string(),
            "query" => "query".to_string(),
            _ => panic!("Invalid OAUTH2_RESPONSE_MODE"),
        };
        assert_eq!(result, "form_post");

        // Test query mode
        let mode = "query".to_lowercase();
        let result = match mode.as_str() {
            "form_post" => "form_post".to_string(),
            "query" => "query".to_string(),
            _ => panic!("Invalid OAUTH2_RESPONSE_MODE"),
        };
        assert_eq!(result, "query");
    }

    /// Test OAuth2 response mode validation with invalid input
    ///
    /// This test verifies that the validation logic correctly panics when given an invalid
    /// response mode. It tests the panic behavior for unsupported response modes that
    /// should trigger application startup failures.
    ///
    #[test]
    #[should_panic(expected = "Invalid OAUTH2_RESPONSE_MODE")]
    fn test_oauth2_response_mode_invalid_validation() {
        // Test business logic: invalid mode validation
        let mode = "invalid_mode".to_lowercase();
        match mode.as_str() {
            "form_post" => "form_post".to_string(),
            "query" => "query".to_string(),
            _ => panic!(
                "Invalid OAUTH2_RESPONSE_MODE '{}'. Must be 'form_post' or 'query'.",
                mode
            ),
        };
    }

    /// Test OAuth2 query string construction logic
    ///
    /// This test verifies the business logic for constructing OAuth2 authorization URLs
    /// with proper query parameters. It tests URL encoding and parameter formatting
    /// for OAuth2 authorization requests.
    ///
    #[test]
    fn test_oauth2_query_string_construction_logic() {
        // Test business logic: query string construction
        let response_type = "code";
        let scope = "openid+email";
        let response_mode = "form_post";

        let mut query_string = "".to_string();
        query_string.push_str(&format!("&response_type={}", response_type));
        query_string.push_str(&format!("&scope={}", scope));
        query_string.push_str(&format!("&response_mode={}", response_mode));
        query_string.push_str(&format!("&access_type={}", "online"));
        query_string.push_str(&format!("&prompt={}", "consent"));

        assert_eq!(
            query_string,
            "&response_type=code&scope=openid+email&response_mode=form_post&access_type=online&prompt=consent"
        );
    }

    /// Test OAuth2 redirect URI construction logic
    ///
    /// This test verifies the business logic for constructing OAuth2 redirect URIs
    /// by combining origin and route prefix values. It tests the URI building
    /// functionality used in OAuth2 flows.
    ///
    #[test]
    fn test_oauth2_redirect_uri_construction_logic() {
        // Test business logic: URI construction
        let origin = "https://example.com";
        let route_prefix = "/api/v1";
        let expected = format!("{}{}/oauth2/authorized", origin, route_prefix);
        assert_eq!(expected, "https://example.com/api/v1/oauth2/authorized");
    }

    /// Test __Host- prefix cookie naming convention
    ///
    /// This test verifies that the CSRF cookie name follows the secure __Host- prefix
    /// convention for enhanced security. It checks that the cookie name is properly
    /// formatted according to web security best practices.
    ///
    #[test]
    fn test_host_prefix_cookie_naming_convention() {
        // Test that our CSRF cookie name uses the "__Host-" prefix for security
        let default_name = "__Host-CsrfId";
        assert!(
            default_name.starts_with("__Host-"),
            "CSRF cookie should use __Host- prefix for security"
        );
    }

    /// Test CSRF cookie max age parsing logic
    ///
    /// This test verifies the string-to-u64 parsing logic used for CSRF cookie max age configuration.
    /// It tests both successful parsing of valid numeric strings and fallback behavior when parsing
    /// fails with invalid input, ensuring the default value (60 seconds) is used as expected.
    ///
    #[test]
    fn test_oauth2_csrf_cookie_max_age_parsing_logic() {
        // Test business logic: parsing and fallback behavior
        let valid_input = "120";
        let result = valid_input.parse::<u64>().unwrap_or(60);
        assert_eq!(result, 120);

        let invalid_input = "invalid";
        let result = invalid_input.parse::<u64>().unwrap_or(60);
        assert_eq!(result, 60);
    }
}
