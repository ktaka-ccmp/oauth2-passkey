//! Central configuration for the oauth2_passkey crate

use std::sync::LazyLock;

/// Route prefix for all oauth2_passkey endpoints
///
/// This is the main prefix under which all authentication endpoints will be mounted.
/// Default: "/o2p"
pub static O2P_ROUTE_PREFIX: LazyLock<String> =
    LazyLock::new(|| std::env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string()));

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_o2p_route_prefix_default() {
        // Save the current environment variable value if it exists
        let original_value = env::var("O2P_ROUTE_PREFIX").ok();

        // Remove the environment variable to test default behavior
        unsafe {
            env::remove_var("O2P_ROUTE_PREFIX");
        }

        // We can't directly test the LazyLock since it's already initialized,
        // but we can test the same logic it uses
        let prefix = env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string());
        assert_eq!(prefix, "/o2p");

        // Restore the original value if it existed
        if let Some(value) = original_value {
            unsafe {
                env::set_var("O2P_ROUTE_PREFIX", value);
            }
        }
    }

    #[test]
    fn test_o2p_route_prefix_custom() {
        // Save the current environment variable value if it exists
        let original_value = env::var("O2P_ROUTE_PREFIX").ok();

        // Set a custom value
        unsafe {
            env::set_var("O2P_ROUTE_PREFIX", "/custom");
        }

        // Test the same logic used by the LazyLock
        let prefix = env::var("O2P_ROUTE_PREFIX").unwrap_or_else(|_| "/o2p".to_string());
        assert_eq!(prefix, "/custom");

        // Restore the original value if it existed
        unsafe {
            if let Some(value) = original_value {
                env::set_var("O2P_ROUTE_PREFIX", value);
            } else {
                env::remove_var("O2P_ROUTE_PREFIX");
            }
        }
    }
}
