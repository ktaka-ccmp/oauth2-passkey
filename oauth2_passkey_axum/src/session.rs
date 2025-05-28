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

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub id: String,
    pub account: String,
    pub label: String,
    pub is_admin: bool,
    pub sequence_number: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub csrf_token: String,
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
