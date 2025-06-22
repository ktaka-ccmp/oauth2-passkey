use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, headers};
use chrono::{DateTime, Utc};
use http::{Method, StatusCode, request::Parts};
use subtle::ConstantTimeEq;

use super::config::O2P_REDIRECT_ANON;
use oauth2_passkey::{SESSION_COOKIE_NAME, SessionUser, get_user_and_csrf_token_from_session};

pub struct AuthRedirect {
    method: Method,
}

impl AuthRedirect {
    fn new(method: Method) -> Self {
        Self { method }
    }

    fn into_response_with_method(self) -> Response {
        if self.method == Method::GET {
            tracing::debug!("Redirecting to {}", O2P_REDIRECT_ANON.as_str());
            Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
        } else {
            tracing::debug!("Unauthorized");
            (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
        }
    }
}

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        tracing::debug!("IntoResponse for AuthRedirect");
        self.into_response_with_method()
    }
}

/// Authenticated user information, available as an Axum extractor
///
/// This struct represents an authenticated user and can be used as an extractor
/// in Axum route handlers. When used as an extractor, it checks for a valid
/// session cookie and automatically verifies CSRF token requirements for state-changing
/// methods (POST, PUT, DELETE, PATCH).
///
/// # Fields
///
/// * `id` - Unique user identifier
/// * `account` - User's account name (email or username)
/// * `label` - User's display name
/// * `is_admin` - Whether the user has admin privileges
/// * `sequence_number` - User version for tracking account changes
/// * `created_at` - When the user account was created
/// * `updated_at` - When the user account was last updated
/// * `csrf_token` - CSRF token associated with the user's session
/// * `csrf_via_header_verified` - Whether CSRF token was verified via header
///
/// # Example
///
/// ```no_run
/// use axum::{routing::get, Router};
/// use oauth2_passkey_axum::AuthUser;
///
/// async fn protected_handler(user: AuthUser) -> String {
///     format!("Hello, {}!", user.label)
/// }
///
/// let app: Router = Router::new()
///     .route("/protected", get(protected_handler));
/// ```
#[derive(Clone, Debug)]
pub struct AuthUser {
    /// Unique user identifier
    pub id: String,
    /// User's account name (email or username)
    pub account: String,
    /// User's display name
    pub label: String,
    /// Whether the user has admin privileges
    pub is_admin: bool,
    /// User version for tracking account changes
    pub sequence_number: i64,
    /// When the user account was created
    pub created_at: DateTime<Utc>,
    /// When the user account was last updated
    pub updated_at: DateTime<Utc>,
    /// CSRF token associated with the user's session
    pub csrf_token: String,
    /// Whether CSRF token was verified via header
    pub csrf_via_header_verified: bool,
}

impl From<&AuthUser> for SessionUser {
    fn from(auth_user: &AuthUser) -> Self {
        SessionUser {
            id: auth_user.id.clone(),
            account: auth_user.account.clone(),
            label: auth_user.label.clone(),
            is_admin: auth_user.is_admin,
            sequence_number: auth_user.sequence_number,
            created_at: auth_user.created_at,
            updated_at: auth_user.updated_at,
        }
    }
}

impl From<SessionUser> for AuthUser {
    fn from(session_user: SessionUser) -> Self {
        AuthUser {
            id: session_user.id,
            account: session_user.account,
            label: session_user.label,
            is_admin: session_user.is_admin,
            sequence_number: session_user.sequence_number,
            created_at: session_user.created_at,
            updated_at: session_user.updated_at,
            csrf_token: String::new(),
            csrf_via_header_verified: false,
        }
    }
}

impl<B> FromRequestParts<B> for AuthUser
where
    B: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, _: &B) -> Result<Self, Self::Rejection> {
        let method = parts.method.clone();
        let cookies: TypedHeader<headers::Cookie> = parts.extract().await.map_err(|_| {
            tracing::error!("Failed to extract cookies");
            AuthRedirect::new(method.clone())
        })?;

        // Get session from cookie
        let session_cookie = cookies.get(SESSION_COOKIE_NAME.as_str()).ok_or_else(|| {
            tracing::error!(
                "Failed to get session cookie: {:?} from cookies: {:#?}",
                SESSION_COOKIE_NAME.as_str(),
                cookies
            );
            AuthRedirect::new(method.clone())
        })?;

        let (session_user, session_csrf_token_str) =
            get_user_and_csrf_token_from_session(session_cookie)
                .await
                .map_err(|_| {
                    tracing::error!("Failed to get user and csrf token from session");
                    AuthRedirect::new(method.clone())
                })?;

        let mut auth_user = AuthUser::from(session_user);
        auth_user.csrf_token = session_csrf_token_str.as_str().to_string(); // Store the session's CSRF token

        // Verify CSRF token for state-changing methods
        if method == Method::POST
            || method == Method::PUT
            || method == Method::DELETE
            || method == Method::PATCH
        {
            if let Some(header_csrf_token) = parts
                .headers
                .get("X-CSRF-Token")
                .and_then(|h| h.to_str().ok())
            {
                // X-CSRF-Token header is present, try to verify it
                if header_csrf_token
                    .as_bytes()
                    .ct_eq(session_csrf_token_str.as_str().as_bytes())
                    .into()
                {
                    auth_user.csrf_via_header_verified = true;
                    tracing::trace!("CSRF token via X-CSRF-Token header verified.");
                } else {
                    tracing::error!(
                        "CSRF token mismatch (X-CSRF-Token). Submitted: {}, Expected: {}",
                        header_csrf_token,
                        session_csrf_token_str.as_str()
                    );
                    return Err(AuthRedirect::new(method.clone())); // Mismatch is an error
                }
            } else {
                // X-CSRF-Token header is NOT present (and we are in a state-changing method context).
                // auth_user.csrf_via_header_verified remains false (its initial value).
                let content_type_header = parts
                    .headers
                    .get(http::header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok());

                let is_form_like = match content_type_header {
                    Some(ct) => {
                        ct.starts_with("application/x-www-form-urlencoded")
                            || ct.starts_with("multipart/form-data")
                    }
                    None => false, // No Content-Type header, assume not form-like for safety
                };

                if is_form_like {
                    // Allowed to proceed for form submissions, CSRF token expected in body.
                    tracing::trace!(
                        "X-CSRF-Token header not found, but Content-Type ('{:?}') is form-like. Form-based CSRF check may be needed in handler.",
                        content_type_header
                    );
                } else {
                    // Not form-like and X-CSRF-Token header is missing. This is a CSRF violation.
                    tracing::warn!(
                        "CSRF protection: X-CSRF-Token header missing for state-changing request with non-form Content-Type ('{:?}'). Rejecting.",
                        content_type_header
                    );
                    return Err(AuthRedirect::new(method.clone())); // Reject
                }
            }
        } else {
            // For GET, HEAD, OPTIONS, etc., no CSRF check needed by default from header.
        }

        Ok(auth_user)
    }
}

impl<B> OptionalFromRequestParts<B> for AuthUser
where
    B: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &B,
    ) -> Result<Option<Self>, Self::Rejection> {
        let result: Result<Self, Self::Rejection> =
            <AuthUser as FromRequestParts<B>>::from_request_parts(parts, state).await;
        Ok(result.ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Test the conversion between SessionUser and AuthUser
    /// This test verifies that all fields are correctly converted between the two types.
    #[test]
    fn test_from_session_user_to_auth_user() {
        // Create a SessionUser instance
        let now = Utc::now();
        let session_user = SessionUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: true,
            sequence_number: 42,
            created_at: now,
            updated_at: now,
        };

        // Convert to AuthUser
        let auth_user = AuthUser::from(session_user);

        // Verify all fields were correctly converted
        assert_eq!(auth_user.id, "user123");
        assert_eq!(auth_user.account, "test@example.com");
        assert_eq!(auth_user.label, "Test User");
        assert!(auth_user.is_admin);
        assert_eq!(auth_user.sequence_number, 42);
        assert_eq!(auth_user.created_at, now);
        assert_eq!(auth_user.updated_at, now);

        // Verify default values for AuthUser-specific fields
        assert_eq!(auth_user.csrf_token, "");
        assert!(!auth_user.csrf_via_header_verified);
    }

    /// Test the conversion from AuthUser to SessionUser
    /// This test verifies that all fields are correctly converted from AuthUser to SessionUser.
    #[test]
    fn test_from_auth_user_to_session_user() {
        // Create an AuthUser instance
        let now = Utc::now();
        let auth_user = AuthUser {
            id: "user123".to_string(),
            account: "test@example.com".to_string(),
            label: "Test User".to_string(),
            is_admin: true,
            sequence_number: 42,
            created_at: now,
            updated_at: now,
            csrf_token: "csrf-token-value".to_string(),
            csrf_via_header_verified: true,
        };

        // Convert to SessionUser
        let session_user = SessionUser::from(&auth_user);

        // Verify all fields were correctly converted
        assert_eq!(session_user.id, "user123");
        assert_eq!(session_user.account, "test@example.com");
        assert_eq!(session_user.label, "Test User");
        assert!(session_user.is_admin);
        assert_eq!(session_user.sequence_number, 42);
        assert_eq!(session_user.created_at, now);
        assert_eq!(session_user.updated_at, now);

        // AuthUser-specific fields should not be present in SessionUser
    }

    /// Test the AuthRedirect struct's new method
    /// This test verifies that the AuthRedirect can be created with different HTTP methods
    #[test]
    fn test_auth_redirect_new() {
        // Test creating AuthRedirect with different HTTP methods
        // We're just testing that the constructor doesn't panic with different methods
        // The variables are prefixed with _ to indicate they're intentionally unused
        let _get_redirect = AuthRedirect::new(Method::GET);
        let _post_redirect = AuthRedirect::new(Method::POST);
        let _put_redirect = AuthRedirect::new(Method::PUT);
        let _delete_redirect = AuthRedirect::new(Method::DELETE);

        // If we get here without panicking, the test passes
        // assert!(true);
    }

    /// Test the AuthRedirect's into_response_with_method method
    /// This test verifies that the method returns the correct response based on the HTTP method.
    #[test]
    fn test_auth_redirect_into_response_with_method() {
        // Test with GET method
        let auth_redirect = AuthRedirect::new(Method::GET);
        let response = auth_redirect.into_response_with_method();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

        // Test with POST method
        let auth_redirect = AuthRedirect::new(Method::POST);
        let response = auth_redirect.into_response_with_method();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Test with PUT method
        let auth_redirect = AuthRedirect::new(Method::PUT);
        let response = auth_redirect.into_response_with_method();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Test with DELETE method
        let auth_redirect = AuthRedirect::new(Method::DELETE);
        let response = auth_redirect.into_response_with_method();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // Note: These tests are marked as ignored because they require the core library's
    // authentication functions which are difficult to mock in a unit test context
}
