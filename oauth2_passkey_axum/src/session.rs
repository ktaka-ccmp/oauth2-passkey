use axum::{
    RequestPartsExt,
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::{TypedHeader, headers};
use http::{request::Parts, Method, StatusCode};

use super::config::O2P_REDIRECT_ANON;
use oauth2_passkey::{SESSION_COOKIE_NAME, SessionError, SessionUser, get_user_from_session};

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
        let cookies: TypedHeader<headers::Cookie> =
            parts.extract().await.map_err(|_| AuthRedirect::new(method.clone()))?;

        // Get session from cookie
        let session_cookie = cookies
            .get(SESSION_COOKIE_NAME.as_str())
            .ok_or(AuthRedirect::new(method.clone()))?;

        // Convert libuserdb::User to libsession::User to AuthUser
        let user: SessionUser = get_user_from_session(&session_cookie)
            .await
            .map_err(|_| AuthRedirect::new(method.clone()))?;
        Ok(AuthUser::from(user))
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
