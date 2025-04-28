mod context_token;
mod csrf;
// mod cookie;
mod session;

use crate::session::{
    config::{USE_CONTEXT_TOKEN_COOKIE, USE_O2P_CSRF_COOKIE},
    errors::SessionError,
};
use http::HeaderMap;

pub(crate) use session::{delete_session_from_store_by_session_id, get_session_id_from_headers};

pub use context_token::{obfuscate_user_id, verify_context_token_and_page};
pub use csrf::verify_csrf_token;
pub use session::{
    get_user_from_session, get_user_from_session_with_user_agent, is_authenticated_basic,
    is_authenticated_strict, prepare_logout_response,
};

pub(crate) async fn new_session_header(
    user_id: String,
    headers: HeaderMap,
) -> Result<HeaderMap, SessionError> {
    let (mut headers, session_id) = session::create_new_session_with_uid(&user_id, headers).await?;

    if *USE_CONTEXT_TOKEN_COOKIE {
        context_token::add_context_token_to_header(&user_id, &mut headers)?;
    }

    if *USE_O2P_CSRF_COOKIE {
        csrf::add_csrf_token_to_header(&user_id, &session_id, &mut headers).await?;
    }

    tracing::debug!("Created session and context token cookies: {headers:?}");

    Ok(headers)
}
