use chrono::{Duration, Utc};
use headers::Cookie;
use http::header::{COOKIE, HeaderMap};

use crate::session::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use crate::session::errors::SessionError;
use crate::session::types::{StoredSession, User as SessionUser};
use crate::utils::{gen_random_string, header_set_cookie};

use crate::storage::GENERIC_CACHE_STORE;
use crate::userdb::UserStore;

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

pub(super) async fn create_new_session_with_uid(
    user_id: &str,
) -> Result<(HeaderMap, String), SessionError> {
    let session_id = gen_random_string(32)?;
    let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);

    let stored_session = StoredSession {
        user_id: user_id.to_string(),
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
    Ok((headers, session_id))
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

/// Check if the request is authenticated by examining the session headers
///
/// This function checks if valid session credentials exist in the request headers
/// without fully loading the user data, making it a lightweight authentication check.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request
/// * `verify_user_exists` - If true, also checks that the user exists in the database (default: false)
///
/// # Returns
/// * `Result<bool, SessionError>` - True if authenticated, false if not authenticated, or an error
async fn is_authenticated(
    headers: &HeaderMap,
    verify_user_exists: bool,
) -> Result<bool, SessionError> {
    // Get session ID from headers
    let Some(session_id) = get_session_id_from_headers(headers)? else {
        return Ok(false);
    };

    // Check if the session exists in the store
    let session_result = GENERIC_CACHE_STORE
        .lock()
        .await
        .get("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    // let _sessions = GENERIC_CACHE_STORE
    //     .lock()
    //     .await
    //     .gets("session", session_id)
    //     .await
    //     .map_err(|e| SessionError::Storage(e.to_string()))?;

    // If no session found, return false
    let Some(cached_session) = session_result else {
        return Ok(false);
    };

    // Convert to StoredSession and check expiration
    let stored_session: StoredSession = match cached_session.try_into() {
        Ok(session) => session,
        Err(_) => return Ok(false),
    };

    // Check if session has expired
    if stored_session.expires_at < Utc::now() {
        tracing::debug!("Session expired at {}", stored_session.expires_at);
        return Ok(false);
    }

    // Optionally check if the user exists in the database
    if verify_user_exists {
        let user_exists = UserStore::get_user(&stored_session.user_id)
            .await
            .map_err(|e| {
                tracing::error!("Error checking user existence: {}", e);
                SessionError::from(e)
            })?
            .is_some();

        Ok(user_exists)
    } else {
        // If we don't need to verify user existence, the session is valid at this point
        Ok(true)
    }
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
pub async fn is_authenticated_basic(headers: &HeaderMap) -> Result<bool, SessionError> {
    is_authenticated(headers, false).await
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
pub async fn is_authenticated_strict(headers: &HeaderMap) -> Result<bool, SessionError> {
    is_authenticated(headers, true).await
}
