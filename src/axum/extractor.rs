use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
    RequestPartsExt,
};
use axum_extra::{headers, TypedHeader};
use http::request::Parts;

use std::convert::Infallible;

use crate::oauth2::SESSION_COOKIE_NAME;
use crate::types::{AppState, User};

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        println!("AuthRedirect called.");
        Redirect::temporary("/").into_response()
    }
}

impl FromRequestParts<AppState> for User {
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let store = &state.session_store;
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|_| AuthRedirect)?;

        // Get session from cookie
        let session_cookie = cookies.get(SESSION_COOKIE_NAME).ok_or(AuthRedirect)?;
        let store_guard = store.lock().await;
        let session = store_guard
            .get(session_cookie)
            .await
            .map_err(|_| AuthRedirect)?;

        // Get user data from session
        let stored_session = session.ok_or(AuthRedirect)?;
        Ok(stored_session.user)
    }
}

impl OptionalFromRequestParts<AppState> for User {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <User as FromRequestParts<AppState>>::from_request_parts(parts, state).await {
            Ok(res) => Ok(Some(res)),
            Err(AuthRedirect) => Ok(None),
        }
    }
}
