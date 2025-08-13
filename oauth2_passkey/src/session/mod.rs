/// Session management components for authentication and user state persistence.
///
/// This module provides session handling capabilities, including creation, validation,
/// and management of user sessions for web applications. It implements secure session
/// cookies with CSRF protection.
///
/// ## Key components:
///
/// - Session cookies: Secure, HTTP-only session cookies
/// - CSRF protection: Token-based cross-site request forgery prevention
/// - User session data: Storing authenticated user information
/// - Session validation: Authentication status verification
/// - Session expiration: Time-based session invalidation
/// - Page session tokens: Additional protection for sensitive operations
///
/// ## Security features:
///
/// - Signed, HTTP-only, secure cookies
/// - Required CSRF tokens for state-changing operations
/// - Session timeouts for both inactivity and absolute duration
/// - Protection against session fixation attacks
mod config;
mod errors;
mod main;
mod types;

pub use config::SESSION_COOKIE_NAME; // Required for cookie configuration
pub use errors::SessionError;
pub use types::{AuthenticationStatus, CsrfHeaderVerified, CsrfToken, SessionId, User, UserId}; // Required for session data

pub use main::{
    generate_page_session_token, get_csrf_token_from_session, get_user_and_csrf_token_from_session,
    get_user_from_session, is_authenticated_basic, is_authenticated_basic_then_csrf,
    is_authenticated_basic_then_user_and_csrf, is_authenticated_strict,
    is_authenticated_strict_then_csrf, prepare_logout_response, verify_page_session_token,
};

#[cfg(test)]
pub(crate) use main::test_utils::{insert_test_session, insert_test_user};

pub(crate) use main::{
    delete_session_from_store_by_session_id, get_session_id_from_headers, new_session_header,
};
