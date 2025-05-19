//! Page session token functionality for session/page synchronization
//!
//! This module provides stateless token generation and verification for
//! ensuring that the user interacting with a page is the same as the
//! user in the session, preventing session/page desynchronization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http::HeaderMap;
use sha2::Sha256;

use crate::{
    session::{config::AUTH_SERVER_SECRET, errors::SessionError, types::StoredSession},
    storage::GENERIC_CACHE_STORE,
};

use super::session::get_session_id_from_headers;

type HmacSha256 = Hmac<Sha256>;

pub fn generate_page_session_token(token: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(token.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

/// Verify that received page_session_token (obfuscated csrf_token) as a part of query param is same as the one
/// in the current user's session cache.
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
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
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
