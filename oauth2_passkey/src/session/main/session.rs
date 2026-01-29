use chrono::{Duration, Utc};
use headers::Cookie;
use http::Method;
use http::header::{COOKIE, HeaderMap};
use subtle::ConstantTimeEq;

use crate::session::config::{
    SESSION_CONFLICT_POLICY, SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME, SessionConflictPolicy,
};
use crate::session::errors::SessionError;
use crate::session::types::{
    AuthenticationStatus, CsrfHeaderVerified, CsrfToken, SessionId, StoredSession,
    User as SessionUser, UserId,
};
use crate::userdb::UserStore;
use crate::utils::{gen_random_string_with_entropy_validation, header_set_cookie};

use crate::storage::{
    CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE, get_data, remove_data,
};

use super::user_sessions::{
    add_session_to_user_mapping, cleanup_stale_sessions, remove_session_from_user_mapping,
};

/// Prepare a logout response by removing the session cookie and deleting the session from storage
///
/// # Arguments
/// * `cookies` - The cookies from the request
///
/// # Returns
/// * `Result<HeaderMap, SessionError>` - The headers with the logout response, or an error
#[tracing::instrument(skip(cookies))]
pub async fn prepare_logout_response(cookies: headers::Cookie) -> Result<HeaderMap, SessionError> {
    tracing::info!("Preparing logout response and clearing session");

    // Before deleting, retrieve session data to get user_id for mapping cleanup
    if let Some(cookie_value) = cookies.get(&SESSION_COOKIE_NAME) {
        let session_id_str = cookie_value.to_string();

        // Try to get user_id from the session before deleting it
        if let Ok(cache_key) = CacheKey::new(session_id_str.clone())
            && let Ok(Some(stored_session)) =
                get_data::<StoredSession, SessionError>(CachePrefix::session(), cache_key).await
        {
            // Remove session from user's mapping
            remove_session_from_user_mapping(&stored_session.user_id, &session_id_str)
                .await
                .ok();
        }
    }

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

#[tracing::instrument(fields(user_id = %user_id.as_str(), session_id))]
pub(super) async fn create_new_session_with_uid(
    user_id: UserId,
) -> Result<HeaderMap, SessionError> {
    tracing::info!("Creating new session for user");
    let user_id_str = user_id.as_str();

    // Clean up stale sessions and apply conflict policy
    let active_sessions = cleanup_stale_sessions(user_id_str).await?;

    if !active_sessions.is_empty() {
        let policy = &*SESSION_CONFLICT_POLICY;
        tracing::debug!(
            "User {} has {} active session(s), policy: {:?}",
            user_id_str,
            active_sessions.len(),
            policy
        );

        match policy {
            SessionConflictPolicy::Allow => {
                // Permit multiple concurrent sessions
            }
            SessionConflictPolicy::Replace => {
                // Delete all existing sessions (also removes them from the mapping)
                for sid in &active_sessions {
                    tracing::info!(
                        "Replacing existing session {} for user {}",
                        sid,
                        user_id_str
                    );
                    if let Ok(session_id) = SessionId::new(sid.clone()) {
                        let _ = delete_session_from_store_by_session_id(session_id).await;
                    }
                }
            }
            SessionConflictPolicy::Reject => {
                tracing::warn!(
                    "Login rejected for user {}: active session exists (policy: reject)",
                    user_id_str
                );
                return Err(SessionError::SessionConflictRejected);
            }
        }
    }

    let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);
    let csrf_token = gen_random_string_with_entropy_validation(32)?;

    let stored_session = StoredSession {
        user_id: user_id_str.to_string(),
        csrf_token: csrf_token.to_string(),
        expires_at,
        ttl: *SESSION_COOKIE_MAX_AGE,
    };

    // Use simplified cache API for auto-generated session keys
    let session_id = crate::storage::store_cache_auto::<_, SessionError>(
        CachePrefix::session(),
        stored_session,
        *SESSION_COOKIE_MAX_AGE,
    )
    .await?
    .as_str()
    .to_string();

    // Add the new session to the user's mapping
    add_session_to_user_mapping(user_id_str, &session_id).await?;

    // Record session_id in the tracing span
    tracing::Span::current().record("session_id", &session_id);

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
        remove_data::<SessionError>(
            CachePrefix::session(),
            CacheKey::new(cookie.to_string()).map_err(SessionError::convert_storage_error)?,
        )
        .await?;
    };
    Ok(())
}

pub(crate) async fn delete_session_from_store_by_session_id(
    session_id: SessionId,
) -> Result<(), SessionError> {
    let session_id_str = session_id.as_str().to_string();

    // Try to get user_id from the session before deleting it for mapping cleanup
    if let Ok(cache_key) = CacheKey::new(session_id_str.clone())
        && let Ok(Some(stored_session)) =
            get_data::<StoredSession, SessionError>(CachePrefix::session(), cache_key).await
    {
        remove_session_from_user_mapping(&stored_session.user_id, &session_id_str)
            .await
            .ok();
    }

    remove_data::<SessionError>(
        CachePrefix::session(),
        CacheKey::new(session_id_str).map_err(SessionError::convert_storage_error)?,
    )
    .await?;
    Ok(())
}

/// Retrieves user information from a session cookie.
///
/// This function takes a session cookie value (not the whole cookie string, just the value)
/// and returns the associated user information if the session is valid.
///
/// # Arguments
///
/// * `session_cookie` - The session cookie value (session ID)
///
/// # Returns
///
/// * `Ok(SessionUser)` - The user information associated with the session
/// * `Err(SessionError)` - If the session is invalid or expired, or if the user doesn't exist
///
/// # Example
/// ```no_run
/// use oauth2_passkey::{get_user_from_session, SessionCookie};
///
/// async fn get_username(session_id: &str) -> Option<String> {
///     let session_cookie = SessionCookie::new(session_id.to_string()).ok()?;
///     match get_user_from_session(&session_cookie).await {
///         Ok(user) => Some(user.account),
///         Err(_) => None
///     }
/// }
/// ```
#[tracing::instrument(fields(session_cookie = %session_cookie.as_str(), user_id))]
pub async fn get_user_from_session(
    session_cookie: &crate::session::types::SessionCookie,
) -> Result<SessionUser, SessionError> {
    tracing::debug!("Retrieving user from session");
    let stored_session = get_data::<StoredSession, SessionError>(
        CachePrefix::session(),
        CacheKey::new(session_cookie.as_str().to_string())
            .map_err(SessionError::convert_storage_error)?,
    )
    .await?
    .ok_or(SessionError::SessionError)?;

    let user_id =
        UserId::new(stored_session.user_id.clone()).map_err(|_| SessionError::SessionError)?;
    let user = UserStore::get_user(user_id)
        .await
        .map_err(|_| SessionError::SessionError)?
        .ok_or(SessionError::SessionError)?;

    // Record user_id in the tracing span
    tracing::Span::current().record("user_id", &user.id);
    tracing::debug!(user_id = %user.id, "Successfully retrieved user from session");

    Ok(SessionUser::from(user))
}

pub(crate) fn get_session_id_from_headers(
    headers: &HeaderMap,
) -> Result<Option<&str>, SessionError> {
    tracing::debug!("Headers: {:#?}", headers);

    let cookie_name = SESSION_COOKIE_NAME.as_str();
    tracing::debug!("Looking for cookie: {}", cookie_name);

    // Get all cookie headers (there might be multiple)
    let cookie_headers: Vec<_> = headers.get_all(COOKIE).iter().collect();

    if cookie_headers.is_empty() {
        tracing::debug!("No cookie header found");
        return Ok(None);
    }

    tracing::debug!("Found {} cookie header(s)", cookie_headers.len());

    // Search through all cookie headers
    for cookie_header in cookie_headers {
        tracing::debug!("Processing cookie header: {:?}", cookie_header);

        let cookie_str = cookie_header.to_str().map_err(|e| {
            tracing::error!("Invalid cookie header: {}", e);
            SessionError::HeaderError("Invalid cookie header".to_string())
        })?;

        // Check if this header contains our target cookie
        // Handle both single cookie and semicolon-separated cookies
        let session_id = cookie_str.split(';').map(|s| s.trim()).find_map(|s| {
            let mut parts = s.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) if k == cookie_name => Some(v),
                _ => None,
            }
        });

        if let Some(session_id) = session_id {
            tracing::debug!(
                "Found session cookie '{}' with value: {}",
                cookie_name,
                session_id
            );
            return Ok(Some(session_id));
        }
    }

    tracing::debug!(
        "No session cookie '{}' found in any cookie headers",
        cookie_name
    );
    Ok(None)
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
) -> Result<
    (
        AuthenticationStatus,
        Option<UserId>,
        Option<CsrfToken>,
        CsrfHeaderVerified,
    ),
    SessionError,
> {
    let session_id = match get_session_id_from_headers(headers)? {
        Some(id) => id,
        None => {
            return Ok((
                AuthenticationStatus(false),
                None,
                None,
                CsrfHeaderVerified(false),
            ));
        } // Not authenticated, no CSRF check done
    };

    // Get session data - Redis TTL handles expiration automatically
    let cache_key =
        CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?;

    let stored_session: StoredSession = match GENERIC_CACHE_STORE
        .lock()
        .await
        .get(CachePrefix::session(), cache_key)
        .await
        .map_err(SessionError::convert_storage_error)?
    {
        Some(session_data) => {
            // Session exists (Redis TTL ensures it's not expired)
            match session_data.try_into() {
                Ok(session) => session,
                Err(_) => {
                    return Ok((
                        AuthenticationStatus(false),
                        None,
                        None,
                        CsrfHeaderVerified(false),
                    )); // Invalid session, no CSRF check done
                }
            }
        }
        None => {
            // Session doesn't exist or was expired and deleted atomically
            tracing::debug!("Session not found or expired: {}", session_id);
            return Ok((
                AuthenticationStatus(false),
                None,
                None,
                CsrfHeaderVerified(false),
            )); // Session not found or expired
        }
    };

    let mut csrf_via_header_verified = false;

    // CSRF validation for state-changing methods
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
        let user_id = UserId::new(stored_session.user_id.clone()).map_err(|e| {
            tracing::error!("Error validating user ID from session: {}", e);
            SessionError::SessionError
        })?;
        let user_exists = UserStore::get_user(user_id)
            .await
            .map_err(|e| {
                tracing::error!("Error checking user existence: {}", e);
                SessionError::from(e)
            })?
            .is_some();

        if !user_exists {
            return Ok((
                AuthenticationStatus(false),
                None,
                None,
                CsrfHeaderVerified(csrf_via_header_verified),
            )); // User not found
        }
    }

    let user_id = UserId::new(stored_session.user_id).map_err(|e| {
        tracing::error!("Error validating user ID from session: {}", e);
        SessionError::SessionError
    })?;

    Ok((
        AuthenticationStatus(true), // Authenticated if we reached here
        Some(user_id),
        Some(CsrfToken::new(stored_session.csrf_token)),
        CsrfHeaderVerified(csrf_via_header_verified),
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
/// Performs basic session authentication without verifying the user exists in the database.
///
/// This function checks if a valid session exists in the request headers without performing
/// additional database verification of the user. It offers a faster but less secure
/// authentication check compared to `is_authenticated_strict`.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request, containing the session cookie
/// * `method` - The HTTP method used for the request (relevant for CSRF protection)
///
/// # Returns
/// * `Result<AuthenticationStatus, SessionError>` - The authentication status or an error
///
/// # Example
/// ```no_run
/// use http::{HeaderMap, Method};
/// use oauth2_passkey::is_authenticated_basic;
///
/// async fn check_auth(headers: &HeaderMap) -> bool {
///     match is_authenticated_basic(headers, &Method::GET).await {
///         Ok(status) => status.0,
///         Err(_) => false
///     }
/// }
/// ```
pub async fn is_authenticated_basic(
    headers: &HeaderMap,
    method: &Method,
) -> Result<AuthenticationStatus, SessionError> {
    let (authenticated, _, _, _) = is_authenticated(headers, method, false).await?;
    Ok(authenticated)
}

/// Performs basic authentication and returns the CSRF token if successful.
///
/// This function performs basic authentication (without database verification) and
/// returns the CSRF token associated with the session along with information about
/// whether the CSRF token was already verified via an HTTP header.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request, containing the session cookie
/// * `method` - The HTTP method used for the request (relevant for CSRF protection)
///
/// # Returns
/// * `Ok((CsrfToken, CsrfHeaderVerified))` - The CSRF token and verification status if authenticated
/// * `Err(SessionError)` - If authentication fails or an error occurs
///
/// # Example
/// ```no_run
/// use http::{HeaderMap, Method};
/// use oauth2_passkey::is_authenticated_basic_then_csrf;
///
/// async fn get_csrf(headers: &HeaderMap) -> Option<String> {
///     match is_authenticated_basic_then_csrf(headers, &Method::GET).await {
///         Ok((csrf_token, _)) => Some(csrf_token.as_str().to_string()),
///         Err(_) => None
///     }
/// }
/// ```
pub async fn is_authenticated_basic_then_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(CsrfToken, CsrfHeaderVerified), SessionError> {
    match is_authenticated(headers, method, false).await? {
        (AuthenticationStatus(true), _, Some(csrf_token), csrf_via_header_verified) => {
            Ok((csrf_token, csrf_via_header_verified))
        }
        _ => Err(SessionError::SessionError),
    }
}

/// Performs strict session authentication, verifying the user exists in the database.
///
/// This function checks if a valid session exists in the request headers and additionally
/// verifies that the user referenced by the session still exists in the database. This
/// provides stronger security guarantees than `is_authenticated_basic` but requires a
/// database query.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request, containing the session cookie
/// * `method` - The HTTP method used for the request (relevant for CSRF protection)
///
/// # Returns
/// * `Result<AuthenticationStatus, SessionError>` - The authentication status or an error
///
/// # Example
/// ```no_run
/// use http::{HeaderMap, Method};
/// use oauth2_passkey::is_authenticated_strict;
///
/// async fn check_auth_strict(headers: &HeaderMap) -> bool {
///     match is_authenticated_strict(headers, &Method::GET).await {
///         Ok(status) => status.0,
///         Err(_) => false
///     }
/// }
/// ```
pub async fn is_authenticated_strict(
    headers: &HeaderMap,
    method: &Method,
) -> Result<AuthenticationStatus, SessionError> {
    let (authenticated, _, _, _) = is_authenticated(headers, method, true).await?;
    Ok(authenticated)
}

/// Performs strict authentication and returns the CSRF token if successful.
///
/// This function performs strict authentication (with database verification) and
/// returns the CSRF token associated with the session along with information about
/// whether the CSRF token was already verified via an HTTP header.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request, containing the session cookie
/// * `method` - The HTTP method used for the request (relevant for CSRF protection)
///
/// # Returns
/// * `Ok((CsrfToken, CsrfHeaderVerified))` - The CSRF token and verification status if authenticated
/// * `Err(SessionError)` - If authentication fails or an error occurs
///
/// # Example
/// ```no_run
/// use http::{HeaderMap, Method};
/// use oauth2_passkey::is_authenticated_strict_then_csrf;
///
/// async fn get_csrf_strict(headers: &HeaderMap) -> Option<String> {
///     match is_authenticated_strict_then_csrf(headers, &Method::GET).await {
///         Ok((csrf_token, _)) => Some(csrf_token.as_str().to_string()),
///         Err(_) => None
///     }
/// }
/// ```
pub async fn is_authenticated_strict_then_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(CsrfToken, CsrfHeaderVerified), SessionError> {
    match is_authenticated(headers, method, true).await? {
        (AuthenticationStatus(true), _, Some(csrf_token), csrf_via_header_verified) => {
            Ok((csrf_token, csrf_via_header_verified))
        }
        _ => Err(SessionError::SessionError),
    }
}

/// Performs authentication and returns the user data and CSRF token.
///
/// This comprehensive function performs authentication, retrieves the user information
/// from the database, and returns the CSRF token - all in one operation. This is useful
/// when you need the authenticated user's details along with the CSRF token.
///
/// # Arguments
/// * `headers` - The HTTP headers from the request, containing the session cookie
/// * `method` - The HTTP method used for the request (relevant for CSRF protection)
///
/// # Returns
/// * `Ok((SessionUser, CsrfToken, CsrfHeaderVerified))` - The user data, CSRF token, and verification status
/// * `Err(SessionError)` - If authentication fails or an error occurs
///
/// # Example
/// ```no_run
/// use http::{HeaderMap, Method};
/// use oauth2_passkey::is_authenticated_basic_then_user_and_csrf;
///
/// async fn get_user_and_csrf(headers: &HeaderMap) -> Option<(String, String)> {
///     match is_authenticated_basic_then_user_and_csrf(headers, &Method::GET).await {
///         Ok((user, csrf_token, _)) => Some((user.account, csrf_token.as_str().to_string())),
///         Err(_) => None
///     }
/// }
/// ```
pub async fn is_authenticated_basic_then_user_and_csrf(
    headers: &HeaderMap,
    method: &Method,
) -> Result<(SessionUser, CsrfToken, CsrfHeaderVerified), SessionError> {
    match is_authenticated(headers, method, false).await? {
        (AuthenticationStatus(true), Some(user_id), Some(csrf_token), csrf_via_header_verified) => {
            // Retrieve the user details from the database
            let user = UserStore::get_user(user_id).await?;
            if let Some(user) = user {
                Ok((user.into(), csrf_token, csrf_via_header_verified))
            } else {
                Err(SessionError::SessionError)
            }
        }
        _ => Err(SessionError::SessionError),
    }
}

/// Retrieves the CSRF token from a session.
///
/// This function takes a session ID and returns the CSRF token associated with the session
/// if the session is valid and not expired.
///
/// # Arguments
/// * `session_id` - The session ID (cookie value)
///
/// # Returns
/// * `Ok(CsrfToken)` - The CSRF token associated with the session
/// * `Err(SessionError)` - If the session is invalid or expired
///
/// # Example
/// ```no_run
/// use oauth2_passkey::{get_csrf_token_from_session, SessionCookie};
///
/// async fn get_token_for_form(session_id: &str) -> Option<String> {
///     let session_cookie = SessionCookie::new(session_id.to_string()).ok()?;
///     match get_csrf_token_from_session(&session_cookie).await {
///         Ok(csrf_token) => Some(csrf_token.as_str().to_string()),
///         Err(_) => None
///     }
/// }
/// ```
#[tracing::instrument(fields(session_cookie = %session_cookie.as_str()))]
pub async fn get_csrf_token_from_session(
    session_cookie: &crate::session::types::SessionCookie,
) -> Result<CsrfToken, SessionError> {
    tracing::debug!("Retrieving CSRF token from session");
    let stored_session = get_data::<StoredSession, SessionError>(
        CachePrefix::session(),
        CacheKey::new(session_cookie.as_str().to_string())
            .map_err(SessionError::convert_storage_error)?,
    )
    .await?
    .ok_or(SessionError::SessionError)?;

    // Check if session is expired
    if stored_session.expires_at < Utc::now() {
        tracing::debug!("Session expired at {}", stored_session.expires_at);
        delete_session_from_store_by_session_id(
            SessionId::new(session_cookie.as_str().to_string())
                .map_err(|_| SessionError::SessionError)?,
        )
        .await?;
        return Err(SessionError::SessionExpiredError);
    }

    Ok(CsrfToken::new(stored_session.csrf_token))
}

/// Retrieves both user information and CSRF token from a session.
///
/// This function is similar to `get_user_from_session`, but it also returns the
/// CSRF token associated with the session. This is useful when you need both the
/// user information and the CSRF token in a single operation.
///
/// # Arguments
/// * `session_id` - The session ID (cookie value)
///
/// # Returns
/// * `Ok((SessionUser, CsrfToken))` - The user information and CSRF token associated with the session
/// * `Err(SessionError)` - If the session is invalid or expired, or if the user doesn't exist
///
/// # Example
/// ```no_run
/// use oauth2_passkey::{get_user_and_csrf_token_from_session, SessionCookie};
///
/// async fn get_user_and_token(session_id: &str) -> Option<(String, String)> {
///     let session_cookie = SessionCookie::new(session_id.to_string()).ok()?;
///     match get_user_and_csrf_token_from_session(&session_cookie).await {
///         Ok((user, csrf_token)) => Some((user.account, csrf_token.as_str().to_string())),
///         Err(_) => None
///     }
/// }
/// ```
pub async fn get_user_and_csrf_token_from_session(
    session_cookie: &crate::session::types::SessionCookie,
) -> Result<(SessionUser, CsrfToken), SessionError> {
    let stored_session = get_data::<StoredSession, SessionError>(
        CachePrefix::session(),
        CacheKey::new(session_cookie.as_str().to_string())
            .map_err(SessionError::convert_storage_error)?,
    )
    .await?
    .ok_or(SessionError::SessionError)?;

    // Check if session is expired
    if stored_session.expires_at < Utc::now() {
        tracing::debug!("Session expired at {}", stored_session.expires_at);
        delete_session_from_store_by_session_id(
            SessionId::new(session_cookie.as_str().to_string())
                .map_err(|_| SessionError::SessionError)?,
        )
        .await?;
        return Err(SessionError::SessionExpiredError);
    }

    let user_id = UserId::new(stored_session.user_id.clone()).map_err(|e| {
        tracing::error!("Error validating user ID from session: {}", e);
        SessionError::SessionError
    })?;
    let user = UserStore::get_user(user_id)
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

#[cfg(test)]
mod tests;
