use http::HeaderMap;

use crate::session::errors::SessionError;

use super::context_token::add_context_token_to_header;
use super::session::create_session_with_uid;

#[tracing::instrument]
pub(crate) async fn renew_session_header(user_id: String) -> Result<HeaderMap, SessionError> {
    // Create session cookie for authentication
    let mut headers = create_session_with_uid(&user_id).await?;

    add_context_token_to_header(&user_id, &mut headers)?;

    tracing::debug!("Created session and context token cookies: {headers:?}");

    Ok(headers)
}
