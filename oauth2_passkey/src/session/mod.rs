// mod common;
mod config;
mod errors;
mod main;
mod types;

pub use config::SESSION_COOKIE_NAME; // Required for cookie configuration
pub use errors::SessionError;
pub use types::{CsrfToken, User}; // Required for session data

pub use main::{
    get_csrf_token_from_session, get_user_and_csrf_token_from_session, get_user_from_session,
    is_authenticated_basic, is_authenticated_basic_then_csrf,
    is_authenticated_basic_then_user_and_csrf, is_authenticated_strict,
    is_authenticated_strict_then_csrf, obfuscate_token, prepare_logout_response,
    verify_context_token,
};

pub(crate) use main::{
    delete_session_from_store_by_session_id, get_session_id_from_headers, new_session_header,
};
