use chrono::{Duration, Utc};
use headers::Cookie;
use http::Method;
use http::header::{COOKIE, HeaderMap};
use subtle::ConstantTimeEq;

use crate::session::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use crate::session::errors::SessionError;
use crate::session::types::{CsrfToken, StoredSession, User as SessionUser, UserId};
use crate::userdb::UserStore;
use crate::utils::{gen_random_string, header_set_cookie};

use crate::storage::GENERIC_CACHE_STORE;

/// Prepare a logout response by removing the session cookie and deleting the session from storage
///
/// # Arguments
/// * `cookies` - The cookies from the request
///
/// # Returns
/// * `Result<HeaderMap, SessionError>` - The headers with the logout response, or an error
pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, SessionError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;
    delete_session_from_store(cookies, SESSION_COOKIE_NAME.to_string()).await?;
    Ok(headers)
}

pub(super) async fn create_new_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {
    let session_id = gen_random_string(32)?;
    let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);

    let csrf_token = gen_random_string(32)?;

    let stored_session = StoredSession {
        user_id: user_id.to_string(),
        csrf_token: csrf_token.to_string(),
        expires_at,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(
            "session",
            &session_id,
            stored_session.into(),
            *SESSION_COOKIE_MAX_AGE as usize,
        )
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        SESSION_COOKIE_NAME.to_string(),
        session_id.clone(),
        expires_at,
        *SESSION_COOKIE_MAX_AGE as i64,
    )?;

    tracing::debug!("Headers: {:#?}", headers);
    Ok(headers)
}

async fn delete_session_from_store(
    cookies: Cookie,
    cookie_name: String,
) -> Result<(), SessionError> {
    if let Some(cookie) = cookies.get(&cookie_name) {
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove("session", cookie)
            .await
            .map_err(|e| SessionError::Storage(e.to_string()))?;
    };
    Ok(())
}

pub(crate) async fn delete_session_from_store_by_session_id(
    session_id: &str,
) -> Result<(), SessionError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(())
}

/// Retrieves the user information from the session
///
/// # Arguments
/// * `session_cookie` - The session cookie from the request
///
/// # Returns
/// * `Result<SessionUser, SessionError>` - The user information from the session, or an error
pub async fn get_user_from_session(session_cookie: &str) -> Result<SessionUser, SessionError> {
    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_cookie)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    let user = UserStore::get_user(&stored_session.user_id)
        .await
        .map_err(|_| SessionError::SessionError)?
        .ok_or(SessionError::SessionError)?;

    Ok(SessionUser::from(user))
}

pub(crate) fn get_session_id_from_headers(
    headers: &HeaderMap,
) -> Result<Option<&str>, SessionError> {
    let Some(cookie_header) = headers.get(COOKIE) else {
        tracing::debug!("No cookie header found");
        return Ok(None);
    };

    let cookie_str = cookie_header.to_str().map_err(|e| {
        tracing::error!("Invalid cookie header: {}", e);
        SessionError::HeaderError("Invalid cookie header".to_string())
    })?;

    let cookie_name = SESSION_COOKIE_NAME.as_str();
    tracing::debug!("Looking for cookie: {}", cookie_name);

    let session_id = cookie_str.split(';').map(|s| s.trim()).find_map(|s| {
        let mut parts = s.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(k), Some(v)) if k == cookie_name => Some(v),
            _ => None,
        }
    });

    if session_id.is_none() {
        tracing::debug!("No session cookie '{}' found in cookies", cookie_name);
    }

    Ok(session_id)
}

/// Core internal function to check session authentication and perform flexible CSRF validation.
///
/// This function verifies the session ID from headers, checks the session store,
/// validates the CSRF token based on method and Content-Type (if header is missing),
/// and optionally verifies user existence.
///
/// Returns a tuple: `(authenticated, Option<UserId>, Option<CsrfToken>, csrf_via_header_verified)`
/// where `csrf_via_header_verified` indicates if the CSRF token was successfully validated via the X-CSRF-Token header.
async fn is_authenticated(
    headers: &HeaderMap,
    method: &Method,
    verify_user_exists: bool,
) -> Result<(bool, Option<UserId>, Option<CsrfToken>, bool), SessionError> {
    let session_id = match get_session_id_from_headers(headers)? {
        Some(id) => id,
        None => return Ok((false, None, None, false)), // Not authenticated, no CSRF check done
    };

    let session_result = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    let Some(cached_session) = session_result else {
        return Ok((false, None, None, false)); // No session, no CSRF check done
    };

    let stored_session: StoredSession = match cached_session.try_into() {
        Ok(session) => session,
        Err(_) => return Ok((false, None, None, false)), // Invalid session, no CSRF check done
    };

    if stored_session.expires_at < Utc::now() {
        tracing::debug!("Session expired at {}", stored_session.expires_at);
        return Ok((false, None, None, false)); // Expired session, no CSRF check done
    }

    let mut csrf_via_header_verified = false;

    if method == Method::POST
        || method == Method::PUT
        || method == Method::DELETE
        || method == Method::PATCH
    {
        if let Some(header_csrf_token_str) =
            headers.get("X-CSRF-Token").and_then(|h| h.to_str().ok())
        {
            // Header is present, compare it
            if header_csrf_token_str
                .as_bytes()
                .ct_eq(stored_session.csrf_token.as_bytes())
                .into()
            {
                csrf_via_header_verified = true;
                tracing::trace!("Flexible CSRF: X-CSRF-Token header verified.");
            } else {
                tracing::debug!(
                    "Flexible CSRF: X-CSRF-Token mismatch. Submitted: {}, Expected: {}",
                    header_csrf_token_str,
                    stored_session.csrf_token
                );
                // Mismatch is a definitive error
                return Err(SessionError::CsrfToken("CSRF token mismatch".to_string()));
            }
        } else {
            // X-CSRF-Token header is NOT present (and we are in a state-changing method context).
            // csrf_via_header_verified remains false (its initial value).
            let content_type_header = headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok());
            let is_form_like = match content_type_header {
                Some(ct) => {
                    let ct_lower = ct.to_lowercase(); // Handle potential case variations and parameters like charset
                    ct_lower.starts_with("application/x-www-form-urlencoded")
                        || ct_lower.starts_with("multipart/form-data")
                }
                None => false, // If no Content-Type for a state-changing request, assume not form-like for safety.
            };

            if !is_form_like {
                tracing::warn!(
                    "Flexible CSRF: X-CSRF-Token header missing and Content-Type ('{:?}') is not form-like for state-changing method ({}). Rejecting.",
                    content_type_header,
                    method
                );
                return Err(SessionError::CsrfToken(
                    "CSRF token header missing for non-form, state-changing request".to_string(),
                ));
            } else {
                tracing::trace!(
                    "Flexible CSRF: X-CSRF-Token header missing. Content-Type ('{:?}') is form-like for state-changing method ({}). Form-based check may be needed.",
                    content_type_header,
                    method
                );
                // Proceed, csrf_via_header_verified is false.
            }
        }
    }

    if verify_user_exists {
        let user_exists = UserStore::get_user(&stored_session.user_id)
            .await
            .map_err(|e| {
                tracing::error!("Error checking user existence: {}", e);
                SessionError::from(e)
            })?
            .is_some();

        if !user_exists {
            return Ok((false, None, None, csrf_via_header_verified)); // User not found
        }
    }

    Ok((
        true, // Authenticated if we reached here
        Some(UserId::new(stored_session.user_id)),
        Some(CsrfToken::new(stored_session.csrf_token)),
        csrf_via_header_verified,
    ))
}

/// Check if the request is authenticated by examining the session headers
///
/// This function checks if valid session credentials exist in the request headers.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request
///
/// # Returns
/// * `Result<bool, SessionError>` - True if authenticated, false if not authenticated, or an error
pub async fn is_authenticated_basic(
    headers: &HeaderMap,
    method: &Method,
) -> Result<bool, SessionError> {
    // The fourth element (csrf_via_header_verified) is ignored here as this function
    // only cares about basic authentication status.
    let (authenticated, _, _, _) = is_authenticated(headers, method, false).await?;
    Ok(authenticated)
}

pub async fn is_authenticated_basic_then_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(CsrfToken, bool), SessionError> {
    // bool is csrf_via_header_verified
    match is_authenticated(headers, method, false).await? {
        (true, _, Some(csrf_token), csrf_via_header_verified) => {
            Ok((csrf_token, csrf_via_header_verified))
        }
        _ => Err(SessionError::SessionError), // Or a more specific error if needed
    }
}

/// Check if the request is authenticated by examining the session headers and verifying user existence
///
/// This function checks if valid session credentials exist in the request headers and verifies that
/// the user exists in the database.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request
///
/// # Returns
/// * `Result<bool, SessionError>` - True if authenticated, false if not authenticated, or an error
pub async fn is_authenticated_strict(
    headers: &HeaderMap,
    method: &Method,
) -> Result<bool, SessionError> {
    // The fourth element (csrf_via_header_verified) is ignored here as this function
    // only cares about basic authentication status (with user verification).
    let (authenticated, _, _, _) = is_authenticated(headers, method, true).await?;
    Ok(authenticated)
}

pub async fn is_authenticated_strict_then_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(CsrfToken, bool), SessionError> {
    // bool is csrf_via_header_verified
    match is_authenticated(headers, method, true).await? {
        (true, _, Some(csrf_token), csrf_via_header_verified) => {
            Ok((csrf_token, csrf_via_header_verified))
        }
        _ => Err(SessionError::SessionError), // Or a more specific error if needed
    }
}

pub async fn is_authenticated_basic_then_user_and_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(SessionUser, CsrfToken, bool), SessionError> {
    // bool is csrf_via_header_verified
    match is_authenticated(headers, method, false).await? {
        (true, Some(user_id), Some(csrf_token), csrf_via_header_verified) => {
            // Retrieve the user details from the database
            let user = UserStore::get_user(user_id.as_str()).await?;
            if let Some(user) = user {
                Ok((user.into(), csrf_token, csrf_via_header_verified))
            } else {
                Err(SessionError::SessionError)
            }
        }
        _ => Err(SessionError::SessionError),
    }
}

pub async fn get_csrf_token_from_session(session_id: &str) -> Result<CsrfToken, SessionError> {
    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    Ok(CsrfToken::new(stored_session.csrf_token))
}

pub async fn get_user_and_csrf_token_from_session(
    session_id: &str,
) -> Result<(SessionUser, CsrfToken), SessionError> {
    let cached_session = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?
        .ok_or(SessionError::SessionError)?;

    let stored_session: StoredSession = cached_session.try_into()?;

    let user = UserStore::get_user(&stored_session.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Error checking user existence: {}", e);
            SessionError::from(e)
        })?
        .ok_or(SessionError::SessionError)?;

    Ok((
        SessionUser::from(user),
        CsrfToken::new(stored_session.csrf_token),
    ))
}
