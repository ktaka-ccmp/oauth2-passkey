use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, headers};
use chrono::{DateTime, Utc};
use http::{Method, StatusCode, request::Parts};

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
        tracing::debug!("AuthRedirect called.");
        if self.method == Method::GET {
            Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
        } else {
            (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
        }
    }
}

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        tracing::debug!("AuthRedirect called.");
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
        let cookies: TypedHeader<headers::Cookie> = parts
            .extract()
            .await
            .map_err(|_| AuthRedirect::new(method.clone()))?;

        // Get session from cookie
        let session_cookie = cookies
            .get(SESSION_COOKIE_NAME.as_str())
            .ok_or(AuthRedirect::new(method.clone()))?;

        let (session_user, csrf_token) = get_user_and_csrf_token_from_session(session_cookie)
            .await
            .map_err(|_| AuthRedirect::new(method.clone()))?;

        // Verify CSRF token for POST, PUT, DELETE requests
        if method == Method::POST || method == Method::PUT || method == Method::DELETE {
            let x_csrf_token = parts
                .headers
                .get("X-Csrf-Token")
                .and_then(|h| h.to_str().ok().map(|s| s.to_string()))
                .ok_or(AuthRedirect::new(method.clone()))?;

            tracing::trace!(
                "CSRF token: X-Csrf-Token: {}, from Session: {}",
                x_csrf_token,
                csrf_token
            );

            if x_csrf_token != csrf_token {
                tracing::error!(
                    "CSRF token mismatch, X-Csrf-Token: {}, from Session: {}",
                    x_csrf_token,
                    csrf_token
                );
                return Err(AuthRedirect::new(method.clone()));
            }
        }

        let mut auth_user = AuthUser::from(session_user);
        auth_user.csrf_token = csrf_token;

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
