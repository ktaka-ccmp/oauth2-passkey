use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, headers};
use http::{Method, StatusCode, request::Parts};

use super::config::O2P_REDIRECT_ANON;
use oauth2_passkey::{
    SESSION_COOKIE_NAME, SessionUser, get_user_and_csrf_token_from_session, get_user_from_session,
};

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

/// A local wrapper around libsession::User to allow implementing foreign traits
#[derive(Clone, Debug)]
pub struct AuthUser(SessionUser);

impl std::ops::Deref for AuthUser {
    type Target = SessionUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SessionUser> for AuthUser {
    fn from(user: SessionUser) -> Self {
        Self(user)
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

        // Verify CSRF token for POST, PUT, DELETE requests
        if method == Method::POST || method == Method::PUT || method == Method::DELETE {
            let (user, csrf_token) = get_user_and_csrf_token_from_session(session_cookie)
                .await
                .map_err(|_| AuthRedirect::new(method.clone()))?;

            let x_csrf_token = parts
                .headers
                .get("X-Csrf-Token")
                .ok_or(AuthRedirect::new(method.clone()))
                .map(|h| h.to_str().unwrap().to_string())
                .map_err(|_| AuthRedirect::new(method.clone()))?;

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
            Ok(AuthUser::from(user))
        } else {
            let user: SessionUser = get_user_from_session(session_cookie)
                .await
                .map_err(|_| AuthRedirect::new(method.clone()))?;
            Ok(AuthUser::from(user))
        }
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

#[derive(Clone, Debug)]
pub struct AuthUserWithCsrfToken {
    pub auth_user: AuthUser,
    pub csrf_token: String,
}

impl<B> FromRequestParts<B> for AuthUserWithCsrfToken
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

        let (user, csrf_token) = get_user_and_csrf_token_from_session(session_cookie)
            .await
            .map_err(|_| AuthRedirect::new(method.clone()))?;

        Ok(AuthUserWithCsrfToken {
            auth_user: AuthUser(user),
            csrf_token,
        })
    }
}

impl<B> OptionalFromRequestParts<B> for AuthUserWithCsrfToken
where
    B: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &B,
    ) -> Result<Option<Self>, Self::Rejection> {
        let result: Result<Self, Self::Rejection> =
            <AuthUserWithCsrfToken as FromRequestParts<B>>::from_request_parts(parts, state).await;
        Ok(result.ok())
    }
}
