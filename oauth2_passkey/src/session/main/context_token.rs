//! User context token functionality for session/page synchronization
//!
//! This module provides stateless token generation and verification for
//! ensuring that the user interacting with a page is the same as the
//! user in the session, preventing session/page desynchronization.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderMap, header::SET_COOKIE};
use sha2::Sha256;
use std::{env, sync::LazyLock};

use headers::{Cookie, HeaderMapExt};

use crate::session::{config::USER_CONTEXT_TOKEN_COOKIE, errors::SessionError};

type HmacSha256 = Hmac<Sha256>;

// We're using a simple string representation for tokens instead of a struct
// to minimize dependencies and complexity

static AUTH_SERVER_SECRET: LazyLock<Vec<u8>> =
    LazyLock::new(|| match env::var("AUTH_SERVER_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => "default_secret_key_change_in_production"
            .to_string()
            .into_bytes(),
    });

static USE_CONTEXT_TOKEN_COOKIE: LazyLock<bool> = LazyLock::new(|| {
    match env::var("USE_CONTEXT_TOKEN_COOKIE") {
        Ok(val) => match val.as_str() {
            "true" => true,
            "false" => false,
            _ => panic!(
                "USE_CONTEXT_TOKEN_COOKIE must be 'true' or 'false', got '{}'.",
                val
            ),
        },
        Err(_) => true, // Default to true when not specified
    }
});

/// Obfuscate user ID to prevent direct exposure
/// # Arguments
/// * `user_id` - The user ID to obfuscate
///
/// # Returns
/// * `String` - The obfuscated user ID
pub fn obfuscate_user_id(user_id: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(user_id.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

fn generate_user_context_token(user_id: &str) -> String {
    let expires_at = Utc::now() + Duration::days(1);
    let expiry_str = expires_at.timestamp().to_string();

    // Obfuscate user ID
    let obfuscated_user_id = obfuscate_user_id(user_id);

    // Create the data string
    let data = format!("{}:{}", obfuscated_user_id, expiry_str);

    // Sign the data with HMAC-SHA256
    let mut mac =
        HmacSha256::new_from_slice(&AUTH_SERVER_SECRET).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_base64 = URL_SAFE_NO_PAD.encode(signature);

    // Format as data:signature
    format!("{}:{}", data, signature_base64)
}

/// Verify the user context token:
/// 1. Verifies that the context user matches the session user ID
/// 2. Verifies that the context token has not expired
/// 3. Verifies that the context signature is valid
fn verify_user_context_token(token: &str, session_user_id: &str) -> Result<(), SessionError> {
    // Parse token parts
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return Err(SessionError::ContextToken(
            "Invalid token format".to_string(),
        ));
    }

    let token_obfuscated_user_id = parts[0];
    let expiry_str = parts[1];
    let signature_base64 = parts[2];

    // Verify obfuscated user ID
    let session_obfuscated_user_id = obfuscate_user_id(session_user_id);
    if token_obfuscated_user_id != session_obfuscated_user_id {
        tracing::debug!(
            "Session desynchronization detected: token user does not match session user"
        );
        return Err(SessionError::ContextToken(
            "Your session has changed since this page was loaded".to_string(),
        ));
    }

    // Check expiration
    let expiry = expiry_str.parse::<i64>().map_err(|_| {
        SessionError::ContextToken("Invalid expiration format in token".to_string())
    })?;

    let now = Utc::now().timestamp();
    if now > expiry {
        return Err(SessionError::ContextToken("Token has expired".to_string()));
    }

    // Verify signature
    let data = format!("{}:{}", token_obfuscated_user_id, expiry_str);
    let mut mac = HmacSha256::new_from_slice(&AUTH_SERVER_SECRET)
        .map_err(|_| SessionError::ContextToken("Failed to create HMAC".to_string()))?;
    mac.update(data.as_bytes());

    let signature = URL_SAFE_NO_PAD
        .decode(signature_base64)
        .map_err(|_| SessionError::ContextToken("Invalid signature encoding".to_string()))?;

    mac.verify_slice(&signature)
        .map_err(|_| SessionError::ContextToken("Invalid token signature".to_string()))?;

    Ok(())
}

pub(super) fn add_context_token_to_header(
    user_id: &str,
    headers: &mut HeaderMap,
) -> Result<(), SessionError> {
    if *USE_CONTEXT_TOKEN_COOKIE {
        let context_headers = create_context_token_cookie(user_id);
        for (key, value) in context_headers.iter() {
            headers.append(key, value.clone());
        }
    }
    Ok(())
}

fn create_context_token_cookie(user_id: &str) -> HeaderMap {
    let token = generate_user_context_token(user_id);
    let mut headers = HeaderMap::new();

    // Create cookie with the token that expires in 1 day
    let cookie = format!(
        "{}={}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict",
        *USER_CONTEXT_TOKEN_COOKIE, token
    );

    // Parse cookie. The parse function is used to convert the cookie string into a HeaderMap.
    match cookie.parse() {
        Ok(cookie_value) => {
            headers.insert(SET_COOKIE, cookie_value);
        }
        Err(e) => {
            tracing::error!("Failed to parse cookie: {}", e);
        }
    }

    headers
}

fn extract_context_token_from_cookies(headers: &HeaderMap) -> Option<String> {
    // Try to extract Cookie header

    let token = headers.typed_get::<Cookie>().and_then(|cookie| {
        // Look for our specific context token cookie
        cookie
            .get(&USER_CONTEXT_TOKEN_COOKIE)
            .map(|s| s.to_string())
    });

    token
}

/// Verifies both context token and page context match the user ID
///
/// This function combines both verification steps:
/// 1. Extracts and verifies the context token from cookies
/// 2. Verifies that any page context (if provided) matches the user ID
///
/// Returns SessionError if verification fails.
///
/// # Arguments
/// * `headers` - The headers to extract the context token from
/// * `page_context` - The page context to verify
/// * `user_id` - The user ID to verify against
///
/// # Returns
/// * `Result<(), SessionError>` - The result of the verification, or an error
pub fn verify_context_token_and_page(
    headers: &HeaderMap,
    page_context: Option<&String>,
    user_id: &str,
) -> Result<(), SessionError> {
    if *USE_CONTEXT_TOKEN_COOKIE {
        // Extract token
        let context_token = extract_context_token_from_cookies(headers)
            .ok_or_else(|| SessionError::ContextToken("Context token missing".to_string()))?;

        // Verify token belongs to user
        verify_user_context_token(&context_token, user_id)?;
    }

    // Verify page context matches user (if provided)
    match page_context {
        // If page context is provided, it must match the obfuscated user ID
        Some(context) if context != &obfuscate_user_id(user_id) => {
            // Some(context) if !context.is_empty() && context != &obfuscate_user_id(user_id) => {
            return Err(SessionError::ContextToken(
                "Page context does not match session user".to_string(),
            ));
        }
        _ => {} // Do nothing for None or matching context
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_verify_token() {
        let user_id = "test-user-123";
        let token = generate_user_context_token(user_id);

        // Verification should succeed with matching user ID
        assert!(verify_user_context_token(&token, user_id).is_ok());

        // Verification should fail with different user ID
        assert!(verify_user_context_token(&token, "different-user").is_err());
    }

    #[test]
    fn test_cookie_creation_and_extraction() {
        let user_id = "test-user-456";
        let headers = create_context_token_cookie(user_id);

        // Check that cookie header was set
        assert!(headers.contains_key(SET_COOKIE));

        // We can't easily test extraction here since it requires parsing
        // the Set-Cookie header into a Cookie header, which is complex in testing
    }
}
