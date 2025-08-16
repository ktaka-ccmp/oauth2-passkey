use chrono::{Duration, Utc};
use headers::Cookie;
use http::Method;
use http::header::{COOKIE, HeaderMap};
use subtle::ConstantTimeEq;

use crate::session::config::{SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME};
use crate::session::errors::SessionError;
use crate::session::types::{
    AuthenticationStatus, CsrfHeaderVerified, CsrfToken, StoredSession, User as SessionUser, UserId,
};
use crate::userdb::UserStore;
use crate::utils::{gen_random_string_with_entropy_validation, header_set_cookie};

use crate::storage::{
    CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE, get_data, remove_data,
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

#[tracing::instrument(fields(user_id, session_id))]
pub(super) async fn create_new_session_with_uid(user_id: &str) -> Result<HeaderMap, SessionError> {
    tracing::info!("Creating new session for user");
    let expires_at = Utc::now() + Duration::seconds(*SESSION_COOKIE_MAX_AGE as i64);
    let csrf_token = gen_random_string_with_entropy_validation(32)?;

    let stored_session = StoredSession {
        user_id: user_id.to_string(),
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
    .await?;

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
    session_id: &str,
) -> Result<(), SessionError> {
    remove_data::<SessionError>(
        CachePrefix::session(),
        CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?,
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

    let user = UserStore::get_user(&stored_session.user_id)
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

    // Use atomic get-and-delete-if-expired to prevent race conditions and ensure expired sessions are rejected
    let cache_key =
        CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?;

    let stored_session: StoredSession = match GENERIC_CACHE_STORE
        .lock()
        .await
        .get_and_delete_if_expired(CachePrefix::session(), cache_key)
        .await
        .map_err(SessionError::convert_storage_error)?
    {
        Some(fresh_session_data) => {
            // Session exists and is not expired
            match fresh_session_data.try_into() {
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
        let user_exists = UserStore::get_user(&stored_session.user_id)
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

    Ok((
        AuthenticationStatus(true), // Authenticated if we reached here
        Some(UserId::new(stored_session.user_id)),
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
        delete_session_from_store_by_session_id(session_cookie.as_str()).await?;
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
        delete_session_from_store_by_session_id(session_cookie.as_str()).await?;
        return Err(SessionError::SessionExpiredError);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_environment;
    use headers::HeaderMapExt;
    use http::header::{HeaderMap, HeaderValue};

    // Helper function to create a header map with a cookie
    fn create_header_map_with_cookie(cookie_name: &str, cookie_value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let cookie_str = format!("{cookie_name}={cookie_value}");
        headers.insert(COOKIE, HeaderValue::from_str(&cookie_str).unwrap());
        headers
    }

    /// Test get_session_id_from_headers
    /// This test verifies that session ID can be correctly extracted from HTTP headers.
    /// It performs the following steps:
    /// 1. Creates header map with valid session cookie
    /// 2. Calls get_session_id_from_headers to extract the session ID
    /// 3. Verifies that the function returns the correct session ID
    #[test]
    fn test_get_session_id_from_headers() {
        // Given a header map with a session cookie
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let session_id = "test_session_id";
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        // When getting the session ID
        let result = get_session_id_from_headers(&headers);

        // Then it should return the session ID
        assert!(result.is_ok());
        let session_id_opt = result.unwrap();
        assert!(session_id_opt.is_some());
        assert_eq!(session_id_opt.unwrap(), session_id);
    }

    /// Test get_session_id_from_headers_no_cookie
    /// This test verifies that session ID extraction handles missing session cookies gracefully.
    /// It performs the following steps:
    /// 1. Creates empty header map without any session cookie
    /// 2. Calls get_session_id_from_headers with empty headers
    /// 3. Verifies that the function returns None (no session ID found)
    #[test]
    fn test_get_session_id_from_headers_no_cookie() {
        // Given a header map without a session cookie
        let headers = HeaderMap::new();

        // When getting the session ID
        let result = get_session_id_from_headers(&headers);

        // Then it should return None (no error)
        assert!(result.is_ok());
        let session_id_opt = result.unwrap();
        assert!(session_id_opt.is_none());
    }

    /// Test get_session_id_from_headers_wrong_cookie
    /// This test verifies that session ID extraction handles incorrect cookie names properly.
    /// It performs the following steps:
    /// 1. Creates header map with a non-session cookie (wrong cookie name)
    /// 2. Calls get_session_id_from_headers with incorrect cookie
    /// 3. Verifies that the function returns None (no session cookie found)
    #[test]
    fn test_get_session_id_from_headers_wrong_cookie() {
        // Given a header map with a non-session cookie
        let headers = create_header_map_with_cookie("wrong_cookie", "value");

        // When getting the session ID
        let result = get_session_id_from_headers(&headers);

        // Then it should return None (no error)
        assert!(result.is_ok());
        let session_id_opt = result.unwrap();
        assert!(session_id_opt.is_none());
    }

    /// Test csrf_token_verification
    /// This test verifies that CSRF token verification works correctly with matching tokens.
    /// It performs the following steps:
    /// 1. Creates stored CSRF token and matching header token
    /// 2. Verifies tokens using constant-time comparison
    /// 3. Confirms that matching tokens are validated successfully
    #[test]
    fn test_csrf_token_verification() {
        // Given a CSRF token in the header and a stored token
        let stored_token = "stored_csrf_token";
        let header_token = "stored_csrf_token";

        // When verifying the tokens
        let mut headers = HeaderMap::new();
        headers.insert("X-CSRF-Token", HeaderValue::from_str(header_token).unwrap());

        // Then the tokens should match in constant time
        let result = header_token.as_bytes().ct_eq(stored_token.as_bytes());
        assert!(bool::from(result));
    }

    /// Test csrf_token_verification_mismatch
    /// This test verifies that CSRF token verification correctly rejects mismatched tokens.
    /// It performs the following steps:
    /// 1. Creates stored CSRF token and different header token
    /// 2. Verifies tokens using constant-time comparison
    /// 3. Confirms that mismatched tokens are properly rejected
    #[test]
    fn test_csrf_token_verification_mismatch() {
        // Given a CSRF token in the header and a different stored token
        let stored_token = "stored_csrf_token";
        let header_token = "different_csrf_token";

        // When verifying the tokens
        let mut headers = HeaderMap::new();
        headers.insert("X-CSRF-Token", HeaderValue::from_str(header_token).unwrap());

        // Then the tokens should not match
        let result = header_token.as_bytes().ct_eq(stored_token.as_bytes());
        assert!(!bool::from(result));
    }

    // Helper function to create a test StoredSession for unit tests
    fn create_test_session(csrf_token: &str, user_id: &str) -> serde_json::Value {
        use chrono::Utc;

        // Create a JSON representation matching StoredSession structure
        serde_json::json!({
            "user_id": user_id,
            "csrf_token": csrf_token,
            "expires_at": (Utc::now() + Duration::hours(1)).to_rfc3339(),
            "ttl": 3600_u64,
        })
    }

    #[cfg(test)]
    use serial_test::serial;

    /// Test get_csrf_token_from_session_success
    /// This test verifies that CSRF tokens can be successfully retrieved from session storage.
    /// It performs the following steps:
    /// 1. Stores test session with CSRF token in cache
    /// 2. Calls get_csrf_token_from_session with valid session ID
    /// 3. Verifies that the correct CSRF token is returned
    #[tokio::test]
    async fn test_get_csrf_token_from_session_success() {
        use crate::storage::CacheData;

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_123";
        let csrf_token = "test_csrf_token_456";

        // Create test session data
        let session_json = create_test_session(csrf_token, "test_user");

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in the global cache store
        let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
        let cache_key = CacheKey::new(session_id.to_string()).unwrap();
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(cache_prefix, cache_key, cache_data, 3600)
            .await
            .unwrap();

        // Test getting CSRF token using global store
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_csrf_token_from_session(&session_cookie).await;

        assert!(result.is_ok());
        let token = result.unwrap();
        assert_eq!(token.as_str(), csrf_token);
    }

    /// Test get_csrf_token_from_session_not_found
    /// This test verifies that CSRF token retrieval handles missing sessions correctly.
    /// It performs the following steps:
    /// 1. Attempts to get CSRF token from non-existent session ID
    /// 2. Calls get_csrf_token_from_session with invalid session
    /// 3. Verifies that the function returns appropriate error for missing session
    #[tokio::test]
    async fn test_get_csrf_token_from_session_not_found() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "nonexistent_session";

        // Test getting CSRF token for nonexistent session using global store
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_csrf_token_from_session(&session_cookie).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::SessionError => {} // This is the expected error
            err => panic!("Expected SessionError::SessionError, got: {err:?}"),
        }
    }

    // Additional tests can be added here for the other refactored functions

    /// Test get_user_and_csrf_token_from_session_success
    /// This test verifies that user data and CSRF tokens can be retrieved from session storage.
    /// It performs the following steps:
    /// 1. Stores test session with user and CSRF token data in cache
    /// 2. Calls get_user_from_session to retrieve user information
    /// 3. Verifies that the function returns appropriate error when user doesn't exist in database
    #[tokio::test]
    async fn test_get_user_from_session_success() {
        use crate::storage::CacheData;

        // Initialize test environment (env + database)
        init_test_environment().await;

        let session_id = "test_session_123";
        let user_id = "test_user_456";
        let csrf_token = "test_csrf_token_789";

        // Create test session data
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in the global cache store
        let cache_prefix = CachePrefix::new("session".to_string()).unwrap();
        let cache_key = CacheKey::new(session_id.to_string()).unwrap();
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(cache_prefix, cache_key, cache_data, 3600)
            .await
            .unwrap();

        // Test the function using global store
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_user_from_session(&session_cookie).await;

        // The function will fail at the UserStore::get_user call since the user doesn't exist
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::SessionError => {} // This is expected since the user doesn't exist in database
            err => panic!("Expected SessionError::SessionError, got: {err:?}"),
        }
    }

    /// Test get_user_from_session_session_not_found
    /// This test verifies that user retrieval handles missing sessions correctly.
    /// It performs the following steps:
    /// 1. Attempts to get user from non-existent session ID
    /// 2. Calls get_user_from_session with invalid session
    /// 3. Verifies that the function returns appropriate SessionError for missing session
    #[tokio::test]
    async fn test_get_user_from_session_session_not_found() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "nonexistent_session";

        // Test getting user for nonexistent session using global store
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_user_from_session(&session_cookie).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::SessionError => {} // This is the expected error
            err => panic!("Expected SessionError::SessionError, got: {err:?}"),
        }
    }

    /// Test create_new_session_with_uid
    /// This test verifies that new session creation works with valid user ID.
    /// It performs the following steps:
    /// 1. Initializes test environment and creates test user in database
    /// 2. Calls create_new_session_with_uid with valid user ID
    /// 3. Verifies that session is created successfully with proper session and CSRF tokens
    #[tokio::test]
    async fn test_create_new_session_with_uid() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let user_id = "test_user_123";

        // Create a new session using global store
        let result = create_new_session_with_uid(user_id).await;

        // Should succeed and return headers with cookie
        assert!(result.is_ok());
        let headers = result.unwrap();

        // Verify there is a cookie header
        assert!(headers.contains_key(http::header::SET_COOKIE));

        // Extract session ID from cookie
        let cookie_header = headers
            .get(http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let session_id = cookie_header
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap();

        // Verify the session was stored in global cache
        let session_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await;

        assert!(session_result.is_ok());
        let session_data = session_result.unwrap();
        assert!(session_data.is_some());

        // Parse session data to verify it contains the user ID
        let session_json: serde_json::Value =
            serde_json::from_str(&session_data.unwrap().value).unwrap();
        assert_eq!(session_json["user_id"].as_str().unwrap(), user_id);
        assert!(session_json.get("csrf_token").is_some());
        assert!(session_json.get("expires_at").is_some());
    }

    /// Test delete_session_from_store_by_session_id
    /// This test verifies that sessions can be deleted from storage by session ID.
    /// It performs the following steps:
    /// 1. Stores test session in cache with session ID
    /// 2. Calls delete_session_from_store_by_session_id to remove the session
    /// 3. Verifies that the session is successfully deleted and no longer exists in storage
    #[tokio::test]
    async fn test_delete_session_from_store_by_session_id() {
        use crate::storage::CacheData;

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_to_delete";
        let user_id = "test_user";
        let csrf_token = "test_csrf_token";

        // Create test session data
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Delete the session by session ID using global store
        let delete_result = delete_session_from_store_by_session_id(session_id).await;

        // Deletion should succeed
        assert!(delete_result.is_ok());

        // Verify session is gone
        let verify_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await;

        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap().is_none());
    }

    /// Test is_authenticated_success
    /// This test verifies that authentication validation works correctly with valid session data.
    /// It performs the following steps:
    /// 1. Stores valid session with CSRF token in cache
    /// 2. Creates HTTP headers with proper session cookie and CSRF token
    /// 3. Calls authentication validation and verifies successful authentication
    #[tokio::test]
    async fn test_is_authenticated_success() {
        use crate::storage::CacheData;
        use http::Method;

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_auth_success";
        let user_id = "test_user_auth";
        let csrf_token = "test_csrf_token_auth";

        // Create test session data with future expiration
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with session cookie
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        // Test with GET method (no CSRF validation needed) using global store
        let result = is_authenticated(&headers, &Method::GET, false).await;

        assert!(result.is_ok());
        let (auth_status, user_id_opt, csrf_token_opt, csrf_header_verified) = result.unwrap();

        assert!(auth_status.0); // Should be authenticated
        assert!(user_id_opt.is_some());
        assert_eq!(user_id_opt.unwrap().as_str(), user_id);
        assert!(csrf_token_opt.is_some());
        assert_eq!(csrf_token_opt.unwrap().as_str(), csrf_token);
        assert!(!csrf_header_verified.0); // No CSRF header validation for GET
    }

    /// Test is_authenticated_no_session_cookie
    /// This test verifies that authentication validation handles missing session cookies correctly.
    /// It performs the following steps:
    /// 1. Creates HTTP headers without any session cookie
    /// 2. Calls is_authenticated with headers missing session information
    /// 3. Verifies that authentication fails gracefully and returns unauthenticated status
    #[tokio::test]
    async fn test_is_authenticated_no_session_cookie() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        // Create headers without session cookie
        let headers = HeaderMap::new();

        // Test authentication without session cookie using global store
        let result = is_authenticated(&headers, &Method::GET, false).await;

        assert!(result.is_ok());
        let (auth_status, user_id_opt, csrf_token_opt, csrf_header_verified) = result.unwrap();

        assert!(!auth_status.0); // Should not be authenticated
        assert!(user_id_opt.is_none());
        assert!(csrf_token_opt.is_none());
        assert!(!csrf_header_verified.0); // No CSRF header validation done
    }

    /// Test is_authenticated_session_not_found
    /// This test verifies that authentication validation handles non-existent sessions correctly.
    /// It performs the following steps:
    /// 1. Creates HTTP headers with session cookie pointing to non-existent session
    /// 2. Calls is_authenticated with invalid session ID
    /// 3. Verifies that authentication fails gracefully for missing session data
    #[tokio::test]
    async fn test_is_authenticated_session_not_found() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let nonexistent_session_id = "nonexistent_session_id";

        // Create headers with session cookie that doesn't exist in cache
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, nonexistent_session_id);

        // Test authentication with nonexistent session using global store
        let result = is_authenticated(&headers, &Method::GET, false).await;

        assert!(result.is_ok());
        let (auth_status, user_id_opt, csrf_token_opt, csrf_header_verified) = result.unwrap();

        assert!(!auth_status.0); // Should not be authenticated
        assert!(user_id_opt.is_none());
        assert!(csrf_token_opt.is_none());
        assert!(!csrf_header_verified.0); // No CSRF header validation done
    }

    /// Test is_authenticated_expired_session
    /// This test verifies that authentication validation correctly handles expired sessions.
    /// It performs the following steps:
    /// 1. Creates session data with expiration time set to 1 hour ago
    /// 2. Stores the expired session in cache and creates appropriate headers
    /// 3. Verifies that authentication fails and expired session is automatically deleted
    #[tokio::test]
    async fn test_is_authenticated_expired_session() {
        use crate::storage::CacheData;
        use chrono::{Duration, Utc};
        use http::Method;

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_expired_session";
        let user_id = "test_user_expired";
        let csrf_token = "test_csrf_token_expired";

        // Create expired session data (expired 1 hour ago)
        let expired_session_json = serde_json::json!({
            "user_id": user_id,
            "csrf_token": csrf_token,
            "expires_at": (Utc::now() - Duration::hours(1)).to_rfc3339(),
            "ttl": 3600_u64,
        });

        // Convert to CacheData with expired timestamp to match the session expiration
        let cache_data = CacheData {
            value: expired_session_json.to_string(),
            expires_at: Utc::now() - Duration::hours(1),
        };

        // Store the expired session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with expired session cookie
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        // Test authentication with expired session using global store
        let result = is_authenticated(&headers, &Method::GET, false).await;

        assert!(result.is_ok());
        let (auth_status, user_id_opt, csrf_token_opt, csrf_header_verified) = result.unwrap();

        assert!(!auth_status.0); // Should not be authenticated
        assert!(user_id_opt.is_none());
        assert!(csrf_token_opt.is_none());
        assert!(!csrf_header_verified.0); // No CSRF header validation done

        // Verify that the expired session was deleted from global cache
        let verify_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await;
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap().is_none()); // Session should be deleted
    }

    /// Test is_authenticated_post_with_valid_csrf_header
    /// This test verifies that authentication validation correctly handles POST requests with valid CSRF tokens.
    /// It performs the following steps:
    /// 1. Stores valid session with CSRF token in cache
    /// 2. Creates POST request headers with matching CSRF token in X-CSRF-Token header
    /// 3. Verifies that authentication succeeds and CSRF header validation passes
    #[tokio::test]
    async fn test_is_authenticated_post_with_valid_csrf_header() {
        use crate::storage::CacheData;
        use http::{HeaderValue, Method};

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_csrf_valid";
        let user_id = "test_user_csrf";
        let csrf_token = "test_csrf_token_valid";

        // Create test session data with future expiration
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with session cookie and CSRF token
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = create_header_map_with_cookie(&cookie_name, session_id);
        headers.insert("X-CSRF-Token", HeaderValue::from_str(csrf_token).unwrap());

        // Test with POST method and valid CSRF header using global store
        let result = is_authenticated(&headers, &Method::POST, false).await;

        assert!(result.is_ok());
        let (auth_status, user_id_opt, csrf_token_opt, csrf_header_verified) = result.unwrap();

        assert!(auth_status.0); // Should be authenticated
        assert!(user_id_opt.is_some());
        assert_eq!(user_id_opt.unwrap().as_str(), user_id);
        assert!(csrf_token_opt.is_some());
        assert_eq!(csrf_token_opt.unwrap().as_str(), csrf_token);
        assert!(csrf_header_verified.0); // CSRF header should be verified for POST
    }

    /// Test is_authenticated_post_with_invalid_csrf_header
    /// This test verifies that authentication validation correctly rejects POST requests with invalid CSRF tokens.
    /// It performs the following steps:
    /// 1. Stores valid session with correct CSRF token in cache
    /// 2. Creates POST request headers with wrong CSRF token in X-CSRF-Token header
    /// 3. Verifies that authentication fails with CSRF token mismatch error
    #[tokio::test]
    async fn test_is_authenticated_post_with_invalid_csrf_header() {
        use crate::storage::CacheData;
        use http::{HeaderValue, Method};

        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let session_id = "test_session_csrf_invalid";
        let user_id = "test_user_csrf";
        let csrf_token = "test_csrf_token_valid";
        let wrong_csrf_token = "wrong_csrf_token_invalid";

        // Create test session data with future expiration
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with session cookie and WRONG CSRF token
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = create_header_map_with_cookie(&cookie_name, session_id);
        headers.insert(
            "X-CSRF-Token",
            HeaderValue::from_str(wrong_csrf_token).unwrap(),
        );

        // Test with POST method and invalid CSRF header using global store
        let result = is_authenticated(&headers, &Method::POST, false).await;

        // Should return an error due to CSRF token mismatch
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::CsrfToken(msg) => {
                assert!(msg.contains("CSRF token mismatch"));
            }
            err => panic!("Expected SessionError::CsrfToken, got: {err:?}"),
        }
    }

    /// Test get_user_and_csrf_token_from_session_success
    /// This test verifies that user and CSRF token can be retrieved together from session storage.
    /// It performs the following steps:
    /// 1. Stores session with user ID and CSRF token in cache
    /// 2. Calls get_user_and_csrf_token_from_session to retrieve both values
    /// 3. Verifies that both user information and CSRF token are returned correctly
    #[tokio::test]
    async fn test_get_user_and_csrf_token_from_session_success() {
        use crate::storage::CacheData;

        // Initialize test environment (env + database)
        init_test_environment().await;

        let session_id = "test_session_user_csrf";
        let user_id = "test_user_combined";
        let csrf_token = "test_csrf_token_combined";

        // Create test session data
        let session_json = create_test_session(csrf_token, user_id);

        // Convert to CacheData
        let cache_data = CacheData {
            value: session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the session in global cache store
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Test getting user and CSRF token using global store
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_user_and_csrf_token_from_session(&session_cookie).await;

        // With .env_test providing SQLite in-memory database, this should succeed
        // if the user exists in the database, or fail gracefully if the user doesn't exist
        match result {
            Ok((user, csrf)) => {
                // If successful, verify the CSRF token matches
                assert_eq!(csrf.as_str(), csrf_token);
                assert_eq!(user.id, user_id);
            }
            Err(SessionError::SessionError) => {
                // This is expected if the user doesn't exist in the database
                // The session was found and parsed correctly, but UserStore::get_user failed
                // This is actually correct behavior for a non-existent user
            }
            Err(err) => {
                panic!("Unexpected error type: {err:?}");
            }
        }
    }

    /// Test get_user_and_csrf_token_from_session_session_not_found
    /// This test verifies that user and CSRF token retrieval handles missing sessions correctly.
    /// It performs the following steps:
    /// 1. Attempts to get user and CSRF token from non-existent session ID
    /// 2. Calls get_user_and_csrf_token_from_session with invalid session
    /// 3. Verifies that the function returns appropriate SessionError for missing session
    #[tokio::test]
    async fn test_get_user_and_csrf_token_from_session_session_not_found() {
        // Initialize test environment (configures global GENERIC_CACHE_STORE)
        init_test_environment().await;

        let nonexistent_session_id = "nonexistent_session_combined";

        // Test getting user and CSRF token for nonexistent session using global store
        let session_cookie = crate::SessionCookie::new(nonexistent_session_id.to_string()).unwrap();
        let result = get_user_and_csrf_token_from_session(&session_cookie).await;

        // Should fail because session doesn't exist
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::SessionError => {} // This is the expected error
            err => panic!("Expected SessionError::SessionError, got: {err:?}"),
        }
    }

    /// Test get_user_and_csrf_token_from_session_expired_session
    /// This test verifies that user and CSRF token retrieval correctly handles expired sessions.
    /// It performs the following steps:
    /// 1. Creates session data with expiration time in the past
    /// 2. Stores expired session and attempts to retrieve user and CSRF token
    /// 3. Verifies that the function properly handles session expiration and cleanup
    #[tokio::test]
    async fn test_get_user_and_csrf_token_from_session_expired_session() {
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;
        let session_id = "expired_session_123";

        // Create an expired session (1 second ago)
        let expired_time = Utc::now() - Duration::seconds(1);
        let expired_session_json = serde_json::json!({
            "user_id": "user123",
            "csrf_token": "csrf_token_456",
            "expires_at": expired_time.to_rfc3339(),
            "ttl": 3600_u64,
        });

        // Convert to CacheData
        let cache_data = CacheData {
            value: expired_session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        // Store the expired session
        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Attempt to get user and CSRF token
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_user_and_csrf_token_from_session(&session_cookie).await;

        // Should return an error for expired session
        assert!(result.is_err());
        match result {
            Err(SessionError::SessionExpiredError) => {} // Expected error for expired session
            other => panic!("Expected SessionError::SessionExpiredError, got: {other:?}"),
        }

        // Verify that the expired session was deleted from the cache
        let cached_session = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session.is_none()); // Expired session should be deleted
    }

    /// Test get_user_and_csrf_token_from_session_invalid_cache_data
    /// This test verifies that user and CSRF token retrieval handles invalid cache data correctly.
    /// It performs the following steps:
    /// 1. Stores session with valid structure but invalid user data
    /// 2. Calls get_user_and_csrf_token_from_session with invalid user reference
    /// 3. Verifies that the function properly handles database lookup failures for invalid users
    #[tokio::test]
    async fn test_get_user_and_csrf_token_from_session_invalid_cache_data() {
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;

        init_test_environment().await;
        let session_id = "invalid_session_123";

        // We can't directly insert invalid JSON into the mock cache since it's type-safe
        // This test verifies the function handles the case where session exists but is invalid
        // In practice, this would be more relevant for external cache stores (Redis, etc.)

        // For now, let's test with a valid session structure but verify error handling
        // when the UserStore operation fails (which we already expect in our current setup)
        let valid_session_json = serde_json::json!({
            "user_id": "invalid_user",
            "csrf_token": "csrf_token_789",
            "expires_at": (Utc::now() + Duration::seconds(300)).to_rfc3339(),
            "ttl": 3600_u64,
        });

        // Convert to CacheData
        let cache_data = CacheData {
            value: valid_session_json.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let result = get_user_and_csrf_token_from_session(&session_cookie).await;

        // Should return an error due to UserStore not being implemented
        assert!(result.is_err());

        // Session should still exist in cache since it wasn't expired
        let cached_session = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session.is_some());
    }

    // Tests that require environment variables (these will fail without proper .env setup)

    /// Test create_new_session_with_uid_success
    /// This test verifies that new session creation works correctly with valid user ID.
    /// It performs the following steps:
    /// 1. Initializes test environment with in-memory stores
    /// 2. Calls create_new_session_with_uid with valid user ID
    /// 3. Verifies that session is created with proper Set-Cookie header and stored in cache
    #[tokio::test]
    async fn test_create_new_session_with_uid_success() {
        use crate::session::types::StoredSession;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::Utc;

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let user_id = "test_user_session_creation";

        // Create a new session
        let result = create_new_session_with_uid(user_id).await;
        assert!(result.is_ok());

        let headers = result.unwrap();

        // Verify Set-Cookie header was created
        let cookie_header = headers.get(http::header::SET_COOKIE).unwrap();
        let cookie_str = cookie_header.to_str().unwrap();

        // Extract session ID from cookie header
        let session_id = cookie_str
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap();

        // Verify session was actually stored in cache
        let cached_session = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();

        assert!(cached_session.is_some());

        // Verify stored session data is correct
        let stored_session: StoredSession = cached_session.unwrap().try_into().unwrap();
        assert_eq!(stored_session.user_id, user_id);
        assert!(!stored_session.csrf_token.is_empty());
        assert!(stored_session.expires_at > Utc::now());
        assert_eq!(
            stored_session.ttl,
            *crate::session::config::SESSION_COOKIE_MAX_AGE
        );

        // Verify cookie contains correct session ID and has proper attributes
        assert!(cookie_str.contains(&format!(
            "{}={}",
            *crate::session::config::SESSION_COOKIE_NAME,
            session_id
        )));
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("Secure"));
        assert!(cookie_str.contains("SameSite=Strict") || cookie_str.contains("SameSite=Lax"));
    }

    /// Test get_csrf_token_from_session_comprehensive
    /// This test verifies comprehensive CSRF token retrieval functionality from session storage.
    /// It performs the following steps:
    /// 1. Creates and stores complete StoredSession with CSRF token in cache
    /// 2. Calls get_csrf_token_from_session to retrieve the CSRF token
    /// 3. Verifies that the correct CSRF token is returned and matches stored value
    #[tokio::test]
    async fn test_get_csrf_token_from_session_comprehensive() {
        use crate::session::types::StoredSession;
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let session_id = "test_session_csrf_retrieval";
        let user_id = "test_user_csrf";
        let expected_csrf_token = "test_csrf_token_12345";

        // Create and store a test session directly in cache
        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: expected_csrf_token.to_string(),
            expires_at: Utc::now() + Duration::seconds(3600),
            ttl: 3600,
        };

        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Test CSRF token retrieval
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let csrf_result = get_csrf_token_from_session(&session_cookie).await;
        assert!(csrf_result.is_ok());

        let csrf_token = csrf_result.unwrap();
        assert_eq!(csrf_token.as_str(), expected_csrf_token);

        // Verify session still exists in cache after retrieval
        let cached_session = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session.is_some());
    }

    /// Test is_authenticated_basic_success
    /// This test verifies basic authentication validation with valid session and GET request.
    /// It performs the following steps:
    /// 1. Creates and stores valid StoredSession with user and CSRF token
    /// 2. Creates GET request headers with proper session cookie
    /// 3. Verifies that authentication succeeds and returns correct user and CSRF information
    #[tokio::test]
    async fn test_is_authenticated_basic_success() {
        use crate::session::types::StoredSession;
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};
        use http::Method;

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let session_id = "test_session_auth_basic";
        let user_id = "test_user_auth_basic";
        let csrf_token = "test_csrf_auth_basic";

        // Create and store a test session directly in cache
        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: csrf_token.to_string(),
            expires_at: Utc::now() + Duration::seconds(3600),
            ttl: 3600,
        };

        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with session cookie
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        // Test GET request (no CSRF required)
        let auth_result = is_authenticated_basic(&headers, &Method::GET).await;
        assert!(auth_result.is_ok());
        assert!(auth_result.unwrap().0); // Should be authenticated

        // Test POST request (CSRF validation will fail due to missing X-CSRF-Token header and non-form Content-Type)
        let auth_result_post = is_authenticated_basic(&headers, &Method::POST).await;
        assert!(auth_result_post.is_err()); // Should fail due to CSRF validation
        match auth_result_post.unwrap_err() {
            SessionError::CsrfToken(_) => {} // Expected CSRF error
            err => panic!("Expected SessionError::CsrfToken, got: {err:?}"),
        }

        // Test with non-existent session
        let headers_invalid = create_header_map_with_cookie(&cookie_name, "non_existent_session");
        let auth_result_invalid = is_authenticated_basic(&headers_invalid, &Method::GET).await;
        assert!(auth_result_invalid.is_ok());
        assert!(!auth_result_invalid.unwrap().0); // Should NOT be authenticated

        // Test with no session cookie
        let empty_headers = http::HeaderMap::new();
        let auth_result_no_cookie = is_authenticated_basic(&empty_headers, &Method::GET).await;
        assert!(auth_result_no_cookie.is_ok());
        assert!(!auth_result_no_cookie.unwrap().0); // Should NOT be authenticated
    }

    /// Test delete_session_from_store_by_session_id_success
    /// This test verifies that session deletion by session ID works correctly.
    /// It performs the following steps:
    /// 1. Creates and stores valid StoredSession in cache
    /// 2. Calls delete_session_from_store_by_session_id to remove the session
    /// 3. Verifies that the session is successfully deleted and no longer exists in cache
    #[tokio::test]
    async fn test_delete_session_from_store_by_session_id_success() {
        use crate::session::types::StoredSession;
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let session_id = "test_session_deletion";
        let user_id = "test_user_deletion";
        let csrf_token = "test_csrf_deletion";

        // Create and store a test session directly in cache
        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: csrf_token.to_string(),
            expires_at: Utc::now() + Duration::seconds(3600),
            ttl: 3600,
        };

        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Verify session exists before deletion
        let cached_session_before = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_before.is_some());

        // Delete the session
        let delete_result = delete_session_from_store_by_session_id(session_id).await;
        assert!(delete_result.is_ok());

        // Verify session was actually removed from cache
        let cached_session_after = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_after.is_none());

        // Test deleting non-existent session (should not error)
        let delete_nonexistent =
            delete_session_from_store_by_session_id("non_existent_session").await;
        assert!(delete_nonexistent.is_ok());
    }

    // Tests that require UserStore (will fail without database environment variables)

    /// Test get_csrf_token_from_session_missing
    /// This test verifies that CSRF token retrieval handles non-existent sessions correctly.
    /// It performs the following steps:
    /// 1. Initializes test environment with in-memory stores
    /// 2. Attempts to retrieve CSRF token from non-existent session ID
    /// 3. Verifies that the function returns appropriate SessionError for missing session
    #[tokio::test]
    async fn test_get_csrf_token_from_session_missing() {
        use crate::test_utils::init_test_environment;

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        // Test retrieving CSRF token from non-existent session
        let session_cookie = crate::SessionCookie::new("non_existent_session".to_string()).unwrap();
        let result = get_csrf_token_from_session(&session_cookie).await;
        assert!(result.is_err());

        match result {
            Err(crate::session::errors::SessionError::SessionError) => {} // Expected error
            other => panic!("Expected SessionError::SessionError, got: {other:?}"),
        }
    }

    /// Test session_expiration_workflow
    /// This test verifies the complete workflow of session expiration detection and cleanup.
    /// It performs the following steps:
    /// 1. Creates session with past expiration time to simulate expired session
    /// 2. Attempts to access expired session through authentication flow
    /// 3. Verifies that expired session is detected, rejected, and automatically cleaned up
    #[tokio::test]
    async fn test_session_expiration_workflow() {
        use crate::session::types::StoredSession;
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};
        use http::Method;

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let session_id = "test_session_expiration";
        let user_id = "test_user_expiration";
        let csrf_token = "test_csrf_expiration";

        // Create an expired session (1 hour in the past)
        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: csrf_token.to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            ttl: 3600,
        };

        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
            expires_at: Utc::now() - Duration::hours(1), // Match the stored session expiration
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Verify session exists before expiration check
        let cached_session_before = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_before.is_some());

        // Test authentication with expired session - should clean up expired session
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        let auth_result = is_authenticated_basic(&headers, &Method::GET).await;
        assert!(auth_result.is_ok());
        assert!(!auth_result.unwrap().0); // Should NOT be authenticated

        // Verify expired session was automatically removed from cache
        let cached_session_after = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_after.is_none());
    }

    /// Test is_authenticated_basic_then_csrf_success
    /// This test verifies authentication flow with both basic validation and CSRF token verification.
    /// It performs the following steps:
    /// 1. Creates and stores valid session with CSRF token
    /// 2. Tests GET request (basic auth) followed by POST request (with CSRF validation)
    /// 3. Verifies that both authentication modes work correctly with the same session
    #[tokio::test]
    async fn test_is_authenticated_basic_then_csrf_success() {
        use crate::session::types::StoredSession;
        use crate::storage::CacheData;
        use crate::storage::GENERIC_CACHE_STORE;
        use crate::test_utils::init_test_environment;
        use chrono::{Duration, Utc};
        use http::Method;

        // Initialize test environment (uses in-memory stores)
        init_test_environment().await;

        let session_id = "test_session_csrf_auth";
        let user_id = "test_user_csrf_auth";
        let csrf_token = "test_csrf_token_auth";

        // Create and store a test session
        let stored_session = StoredSession {
            user_id: user_id.to_string(),
            csrf_token: csrf_token.to_string(),
            expires_at: Utc::now() + Duration::seconds(3600),
            ttl: 3600,
        };

        let cache_data = CacheData {
            value: serde_json::to_string(&stored_session).unwrap(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Create headers with session cookie and correct CSRF token
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );
        headers.insert("X-CSRF-Token", csrf_token.parse().unwrap());

        // Test successful authentication with CSRF
        let auth_result = is_authenticated_basic_then_csrf(&headers, &Method::POST).await;
        assert!(auth_result.is_ok());

        let (returned_csrf_token, csrf_header_verified) = auth_result.unwrap();
        assert_eq!(returned_csrf_token.as_str(), csrf_token);
        assert!(csrf_header_verified.0); // CSRF was verified via header

        // Test with wrong CSRF token - should fail
        let mut headers_wrong_csrf = http::HeaderMap::new();
        headers_wrong_csrf.insert(
            http::header::COOKIE,
            format!("{}={}", &cookie_name, session_id).parse().unwrap(),
        );
        headers_wrong_csrf.insert("X-CSRF-Token", "wrong_token".parse().unwrap());

        let auth_result_wrong =
            is_authenticated_basic_then_csrf(&headers_wrong_csrf, &Method::POST).await;
        assert!(auth_result_wrong.is_err());

        match auth_result_wrong {
            Err(crate::session::errors::SessionError::CsrfToken(_)) => {} // Expected error
            other => panic!("Expected SessionError::CsrfToken, got: {other:?}"),
        }
    }

    /// Test prepare_logout_response_success
    /// This test verifies that logout response preparation works correctly with valid session.
    /// It performs the following steps:
    /// 1. Creates and stores valid session in cache
    /// 2. Calls prepare_logout_response with session cookie
    /// 3. Verifies that logout response is prepared correctly and session is removed from cache
    #[tokio::test]
    #[serial]
    async fn test_prepare_logout_response_success() {
        use crate::storage::CacheData;
        use headers::Cookie;

        // Initialize the test environment
        init_test_environment().await;

        // Create a new session and store it in the cache
        let csrf_token = "test_csrf_token";
        let user_id = "test_user_id";
        let session_id = "test_session_id";
        let session = create_test_session(csrf_token, user_id);

        // Convert JSON to CacheData for storage
        let cache_data = CacheData {
            value: session.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
                cache_data,
                3600,
            )
            .await
            .unwrap();

        // Verify session exists in cache before logout
        let cached_session_before = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_before.is_some());

        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("{}={}", SESSION_COOKIE_NAME.as_str(), session_id))
                .unwrap(),
        );

        let cookie = headers
            .typed_get::<Cookie>()
            .expect("Failed to parse cookie");
        assert_eq!(
            cookie.get(SESSION_COOKIE_NAME.as_str()).unwrap(),
            session_id
        );

        let logout_result = prepare_logout_response(cookie).await;
        assert!(logout_result.is_ok());

        let headers = logout_result.unwrap();

        // Verify logout cookie header is set (with expiration in the past)
        let set_cookie_header = headers.get(http::header::SET_COOKIE).unwrap();
        let cookie_str = set_cookie_header.to_str().unwrap();
        assert!(cookie_str.contains(SESSION_COOKIE_NAME.as_str()));
        assert!(cookie_str.contains("Max-Age=-86400")); // Expired cookie

        // Verify the session was removed from cache
        let cached_session_after = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(
                CachePrefix::session(),
                CacheKey::new(session_id.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert!(cached_session_after.is_none());
    }

    /// Test get_user_from_session_requires_database
    /// This test verifies that user retrieval from session works correctly with database integration.
    /// It performs the following steps:
    /// 1. Creates test user in database and stores session in cache
    /// 2. Calls get_user_from_session to retrieve user information
    /// 3. Verifies that user data is correctly retrieved when session and user exist in their respective stores
    #[tokio::test]
    #[serial]
    async fn test_get_user_from_session_requires_database() {
        use crate::session::main::test_utils::{
            cleanup_test_resources, create_test_user_and_session,
        };

        // Initialize test environment
        init_test_environment().await;

        // Create test user and session
        let user_id = "test_user_database";
        let account = "test@example.com";
        let label = "Test User";
        let is_admin = false;
        let session_id = "test_session_database_123";
        let csrf_token = "test_csrf_token_database";
        let ttl = 3600;

        // Insert test user and session
        let user = create_test_user_and_session(
            user_id, account, label, is_admin, session_id, csrf_token, ttl,
        )
        .await;
        assert!(user.is_ok());

        // Now test getting the user from session
        let session_cookie = crate::SessionCookie::new(session_id.to_string()).unwrap();
        let user_result = get_user_from_session(&session_cookie).await;

        // Should succeed now that we have added the user to the database
        assert!(user_result.is_ok());
        let session_user = user_result.unwrap();

        // Verify retrieved user data
        assert_eq!(session_user.id, user_id);
        assert_eq!(session_user.account, account);
        assert_eq!(session_user.label, label);
        assert_eq!(session_user.is_admin, is_admin);

        // Clean up test resources
        let _ = cleanup_test_resources(user_id, session_id).await;
    }

    /// Test is_authenticated_strict_requires_database
    /// This test verifies that strict authentication works correctly with database integration.
    /// It performs the following steps:
    /// 1. Creates test user in database and establishes valid session
    /// 2. Calls is_authenticated_strict with proper session cookie
    /// 3. Verifies that strict authentication succeeds when both session and user exist in their stores
    #[tokio::test]
    async fn test_is_authenticated_strict_requires_database() {
        use crate::session::main::test_utils::{
            cleanup_test_resources, create_test_user_and_session,
        };

        // Initialize test environment
        init_test_environment().await;

        // Test case 1: User exists in database - should authenticate
        let user_id = "test_user_strict_auth";
        let account = "strict_auth@example.com";
        let label = "Strict Auth User";
        let is_admin = false;
        let session_id = "test_strict_auth_session";
        let csrf_token = "test_csrf_token_strict_auth";
        let ttl = 3600;

        // Insert test user and session
        let user = create_test_user_and_session(
            user_id, account, label, is_admin, session_id, csrf_token, ttl,
        )
        .await;
        assert!(user.is_ok());

        // Create headers with session cookie
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let headers = create_header_map_with_cookie(&cookie_name, session_id);

        // Test strict authentication - should succeed now that user exists
        let auth_result = is_authenticated_strict(&headers, &Method::GET).await;
        assert!(auth_result.is_ok());
        assert!(auth_result.unwrap().0); // Should BE authenticated

        // Test case 2: Session exists but user doesn't - should not authenticate
        let nonexistent_user_id = "nonexistent_user";
        let nonexistent_session_id = "nonexistent_session";
        let nonexistent_csrf = "nonexistent_csrf";

        // Create session but don't create the user in database
        let _ = crate::session::main::test_utils::insert_test_session(
            nonexistent_session_id,
            nonexistent_user_id,
            nonexistent_csrf,
            ttl,
        )
        .await;

        // Create headers for nonexistent user
        let headers = create_header_map_with_cookie(&cookie_name, nonexistent_session_id);

        // Test strict authentication - should fail since user doesn't exist
        let auth_result = is_authenticated_strict(&headers, &Method::GET).await;
        assert!(auth_result.is_ok());
        assert!(!auth_result.unwrap().0); // Should NOT be authenticated

        // Clean up test resources
        let _ = cleanup_test_resources(user_id, session_id).await;
        let _ = crate::session::main::test_utils::delete_test_session(nonexistent_session_id).await;
    }

    /// Test get_session_id_from_headers_multiple_cookie_headers
    /// This test verifies that session ID extraction works with multiple cookie headers (case A).
    /// It performs the following steps:
    /// 1. Creates header map with multiple cookie headers, one containing session cookie
    /// 2. Calls get_session_id_from_headers to extract the session ID
    /// 3. Verifies that the function returns the correct session ID from the appropriate header
    #[test]
    fn test_get_session_id_from_headers_multiple_cookie_headers() {
        // Given a header map with multiple cookie headers
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let session_id = "test_session_id_multiple";
        let mut headers = HeaderMap::new();

        // Add multiple cookie headers like in case A
        headers.append(
            COOKIE,
            HeaderValue::from_str("_ga=GA1.1.233748741.1749009840").unwrap(),
        );
        headers.append(
            COOKIE,
            HeaderValue::from_str("_ga_ZN78TEJMRW=GS2.1.s1749072867").unwrap(),
        );
        headers.append(
            COOKIE,
            HeaderValue::from_str(&format!("{cookie_name}={session_id}")).unwrap(),
        );
        headers.append(
            COOKIE,
            HeaderValue::from_str("other_cookie=other_value").unwrap(),
        );

        // When getting the session ID
        let result = get_session_id_from_headers(&headers);

        // Then it should return the session ID from the correct header
        assert!(result.is_ok());
        let session_id_opt = result.unwrap();
        assert!(session_id_opt.is_some());
        assert_eq!(session_id_opt.unwrap(), session_id);
    }

    /// Test get_session_id_from_headers_semicolon_separated
    /// This test verifies that session ID extraction works with semicolon-separated cookies (case B).
    /// It performs the following steps:
    /// 1. Creates header map with single cookie header containing multiple semicolon-separated cookies
    /// 2. Calls get_session_id_from_headers to extract the session ID
    /// 3. Verifies that the function returns the correct session ID from the combined header
    #[test]
    fn test_get_session_id_from_headers_semicolon_separated() {
        // Given a header map with semicolon-separated cookies like in case B
        let cookie_name = SESSION_COOKIE_NAME.to_string();
        let session_id = "test_session_id_semicolon";
        let cookie_str = format!(
            "_ga=GA1.1.2096617346; other_cookie=value; {cookie_name}={session_id}; final_cookie=final_value"
        );
        let headers = create_header_map_with_cookie_string(&cookie_str);

        // When getting the session ID
        let result = get_session_id_from_headers(&headers);

        // Then it should return the session ID from the semicolon-separated string
        assert!(result.is_ok());
        let session_id_opt = result.unwrap();
        assert!(session_id_opt.is_some());
        assert_eq!(session_id_opt.unwrap(), session_id);
    }

    // Helper function to create a header map with a complete cookie string
    fn create_header_map_with_cookie_string(cookie_str: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_str(cookie_str).unwrap());
        headers
    }
}
