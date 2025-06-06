//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

use oauth2_passkey::O2P_ROUTE_PREFIX;

/// URL of supplementary login page
/// Default: "/o2p/user/login"
pub static O2P_LOGIN_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_LOGIN_URL").unwrap_or_else(|_| format!("{}/user/login", *O2P_ROUTE_PREFIX))
});

/// URL of supplementary summary page
/// Default: "/o2p/user/summary"
pub static O2P_SUMMARY_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_SUMMARY_URL")
        .unwrap_or_else(|_| format!("{}/user/summary", *O2P_ROUTE_PREFIX))
});

pub static O2P_ADMIN_URL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("O2P_ADMIN_URL")
        .unwrap_or_else(|_| format!("{}/admin/list_users", *O2P_ROUTE_PREFIX))
});

pub static O2P_REDIRECT_ANON: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_REDIRECT_ANON").unwrap_or_else(|_| "/".to_string()));

pub static O2P_RESPOND_WITH_X_CSRF_TOKEN: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("O2P_RESPOND_WITH_X_CSRF_TOKEN")
        .map(|val| val.to_lowercase() != "false")
        .unwrap_or(true)
});

#[cfg(test)]
mod tests {

    // Helper functions that replicate the logic of the LazyLock initializers
    // so we can test them without modifying environment variables

    fn get_login_url(route_prefix: &str, env_value: Option<&str>) -> String {
        env_value
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}/user/login", route_prefix))
    }

    fn get_summary_url(route_prefix: &str, env_value: Option<&str>) -> String {
        env_value
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}/user/summary", route_prefix))
    }

    fn get_admin_url(route_prefix: &str, env_value: Option<&str>) -> String {
        env_value
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}/admin/list_users", route_prefix))
    }

    fn get_redirect_anon(env_value: Option<&str>) -> String {
        env_value
            .map(|s| s.to_string())
            .unwrap_or_else(|| "/".to_string())
    }

    fn get_respond_with_x_csrf_token(env_value: Option<&str>) -> bool {
        env_value
            .map(|val| val.to_lowercase() != "false")
            .unwrap_or(true)
    }

    #[test]
    fn test_login_url_default() {
        let url = get_login_url("/o2p", None);
        assert_eq!(url, "/o2p/user/login");
    }

    #[test]
    fn test_login_url_custom() {
        let url = get_login_url("/o2p", Some("/custom/login"));
        assert_eq!(url, "/custom/login");
    }

    #[test]
    fn test_summary_url_default() {
        let url = get_summary_url("/o2p", None);
        assert_eq!(url, "/o2p/user/summary");
    }

    #[test]
    fn test_summary_url_custom() {
        let url = get_summary_url("/o2p", Some("/custom/summary"));
        assert_eq!(url, "/custom/summary");
    }

    #[test]
    fn test_admin_url_default() {
        let url = get_admin_url("/o2p", None);
        assert_eq!(url, "/o2p/admin/list_users");
    }

    #[test]
    fn test_admin_url_custom() {
        let url = get_admin_url("/o2p", Some("/custom/admin"));
        assert_eq!(url, "/custom/admin");
    }

    #[test]
    fn test_redirect_anon_default() {
        let url = get_redirect_anon(None);
        assert_eq!(url, "/");
    }

    #[test]
    fn test_redirect_anon_custom() {
        let url = get_redirect_anon(Some("/custom/login"));
        assert_eq!(url, "/custom/login");
    }

    #[test]
    fn test_respond_with_x_csrf_token_default() {
        let enabled = get_respond_with_x_csrf_token(None);
        assert!(enabled);
    }

    #[test]
    fn test_respond_with_x_csrf_token_false() {
        let enabled = get_respond_with_x_csrf_token(Some("false"));
        assert!(!enabled);
    }

    #[test]
    fn test_respond_with_x_csrf_token_true() {
        let enabled = get_respond_with_x_csrf_token(Some("true"));
        assert!(enabled);
    }

    #[test]
    fn test_respond_with_x_csrf_token_other_value() {
        // Any value other than "false" (case-insensitive) should be treated as true
        let enabled = get_respond_with_x_csrf_token(Some("anything"));
        assert!(enabled);
    }
}
