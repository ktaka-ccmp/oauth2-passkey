mod context_token;
mod session;

use crate::session::errors::SessionError;
use http::HeaderMap;

pub(crate) use session::{delete_session_from_store_by_session_id, get_session_id_from_headers};

pub use context_token::{obfuscate_token, verify_context_token};
pub use session::{
    get_csrf_token_from_session, get_user_and_csrf_token_from_session, get_user_from_session,
    is_authenticated_basic, is_authenticated_basic_then_csrf,
    is_authenticated_basic_then_user_and_csrf, is_authenticated_strict,
    is_authenticated_strict_then_csrf, prepare_logout_response,
};

pub(crate) async fn new_session_header(user_id: String) -> Result<HeaderMap, SessionError> {
    let headers = session::create_new_session_with_uid(&user_id).await?;
    tracing::debug!("Created session and context token cookies: {headers:?}");

    Ok(headers)
}

// pub(crate) use session::create_new_session_with_uid as new_session_header;
