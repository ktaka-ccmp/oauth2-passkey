//! Page session token functionality for session/page synchronization
//!
//! This module provides stateless token generation and verification for
//! ensuring that the user interacting with a page is the same as the
//! user in the session, preventing session/page desynchronization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use http::HeaderMap;
use sha2::Sha256;

use crate::{
    session::{config::AUTH_SERVER_SECRET, errors::SessionError, types::StoredSession},
    storage::{CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE},
};

use super::session::get_session_id_from_headers;

type HmacSha256 = Hmac<Sha256>;

/// Generates a page session token for synchronizing sessions across pages.
///
/// This function generates a cryptographic hash of the provided token (typically a CSRF token)
/// using HMAC-SHA256 with the server's secret key. The result is a Base64-encoded string
/// that can be included in URLs or forms to ensure the page and session are synchronized.
///
/// # Arguments
/// * `token` - The token to hash (typically a CSRF token)
///
/// # Returns
/// * A Base64-encoded HMAC-SHA256 hash of the token
///
/// # Example
/// ```no_run
/// use oauth2_passkey::{get_csrf_token_from_session, generate_page_session_token, SessionCookie};
///
/// async fn create_secure_link(session_id: &str) -> Option<String> {
///     let session_cookie = SessionCookie::new(session_id.to_string()).ok()?;
///     match get_csrf_token_from_session(&session_cookie).await {
///         Ok(csrf_token) => {
///             let page_token = generate_page_session_token(csrf_token.as_str());
///             Some(format!("/secure-page?token={}", page_token))
///         },
///         Err(_) => None
///     }
/// }
/// ```
pub fn generate_page_session_token(token: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

/// Verifies that a page session token matches the current session's CSRF token.
///
/// This function verifies that the provided page session token (typically from a URL parameter)
/// corresponds to the CSRF token in the user's current session. This helps prevent session/page
/// desynchronization attacks where a user might be tricked into performing actions in the wrong session.
///
/// # Arguments
/// * `headers` - HTTP headers containing the session cookie
/// * `page_session_token` - The page session token to verify (from URL parameter or form)
///
/// # Returns
/// * `Ok(())` - If the token is valid for the current session
/// * `Err(SessionError)` - If the token is invalid, the session is missing, or another error occurs
///
/// # Example
/// ```no_run
/// use http::HeaderMap;
/// use oauth2_passkey::verify_page_session_token;
///
/// async fn validate_page_access(headers: &HeaderMap, token: &String) -> bool {
///     verify_page_session_token(headers, Some(token)).await.is_ok()
/// }
/// ```
pub async fn verify_page_session_token(
    headers: &HeaderMap,
    page_session_token: Option<&String>,
) -> Result<(), SessionError> {
    let session_id: &str = match get_session_id_from_headers(headers) {
        Ok(Some(session_id)) => session_id,
        _ => {
            return Err(SessionError::PageSessionToken(
                "Session ID missing".to_string(),
            ));
        }
    };

    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get(
            CachePrefix::session(),
            CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?,
        )
        .await
        .map_err(SessionError::convert_storage_error)?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    match page_session_token {
        Some(context) => {
            if context.as_str() != generate_page_session_token(&stored_session.csrf_token) {
                tracing::error!("Page session token does not match session user");
                return Err(SessionError::PageSessionToken(
                    "Page session token does not match session user".to_string(),
                ));
            }
        }
        None => {
            tracing::error!("Page session token missing");
            return Err(SessionError::PageSessionToken(
                "Page session token missing".to_string(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;
