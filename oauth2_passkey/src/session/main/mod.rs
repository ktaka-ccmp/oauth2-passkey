mod page_session_token;
mod session;
#[cfg(test)]
mod session_edge_cases_tests;
#[cfg(test)]
mod session_security_tests;
#[cfg(test)]
pub(crate) mod test_utils;
pub(super) mod user_sessions;

use crate::session::errors::SessionError;
use crate::session::types::UserId;

pub(crate) use session::{delete_session_from_store_by_session_id, get_session_id_from_headers};

pub use page_session_token::{generate_page_session_token, verify_page_session_token};
pub use session::{
    SessionCreationResponse, get_csrf_token_from_session, get_user_and_csrf_token_from_session,
    get_user_from_session, is_authenticated_basic, is_authenticated_basic_then_csrf,
    is_authenticated_basic_then_user_and_csrf, is_authenticated_strict,
    is_authenticated_strict_then_csrf, prepare_logout_response,
};

pub(crate) async fn new_session_response(
    user_id: UserId,
) -> Result<SessionCreationResponse, SessionError> {
    let response = session::create_new_session_with_uid(user_id).await?;
    tracing::debug!("Created session response: {response:?}");

    Ok(response)
}
