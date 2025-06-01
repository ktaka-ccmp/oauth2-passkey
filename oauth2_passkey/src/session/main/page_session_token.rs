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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_page_session_token() {
        // Given a CSRF token
        let csrf_token = "test_csrf_token";

        // When generating a page session token
        let page_token = generate_page_session_token(csrf_token);

        // Then the token should be a non-empty string
        assert!(!page_token.is_empty());

        // And generating the token again with the same input should produce the same output
        let page_token2 = generate_page_session_token(csrf_token);
        assert_eq!(page_token, page_token2);

        // And different inputs should produce different outputs
        let different_token = generate_page_session_token("different_token");
        assert_ne!(page_token, different_token);
    }

    #[test]
    fn test_generate_page_session_token_hmac_properties() {
        // Given two similar CSRF tokens
        let token1 = "token1";
        let token2 = "token2";

        // When generating page session tokens
        let page_token1 = generate_page_session_token(token1);
        let page_token2 = generate_page_session_token(token2);

        // Then the tokens should be different (avalanche effect)
        assert_ne!(page_token1, page_token2);

        // And the tokens should be URL-safe (no +, /, or = characters)
        assert!(!page_token1.contains('+'));
        assert!(!page_token1.contains('/'));
        assert!(!page_token1.contains('='));
        assert!(!page_token2.contains('+'));
        assert!(!page_token2.contains('/'));
        assert!(!page_token2.contains('='));
    }

    #[test]
    fn test_generate_page_session_token_with_empty_string() {
        // Given an empty CSRF token
        let empty_token = "";

        // When generating a page session token
        let page_token = generate_page_session_token(empty_token);

        // Then the token should still be a non-empty string
        assert!(!page_token.is_empty());
    }

    // Note: We can't easily test verify_page_session_token directly because it depends on
    // GENERIC_CACHE_STORE which is a global singleton. We would need to mock this dependency
    // for proper unit testing. This would be a good candidate for integration testing.
}
