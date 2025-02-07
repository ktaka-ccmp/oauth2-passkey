use axum::{
    extract::{FromRef, FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Redirect, Response},
    RequestPartsExt,
};
use axum_extra::{headers, TypedHeader};
use http::request::Parts;

use std::convert::Infallible;

use super::engine::{self, User};

use std::sync::Arc;
use tokio::sync::Mutex;

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        println!("AuthRedirect called.");
        Redirect::temporary("/").into_response()
    }
}

impl<S> FromRequestParts<S> for User
where
    Arc<Mutex<Box<dyn crate::storage::CacheStoreSession>>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = Arc::<Mutex<Box<dyn crate::storage::CacheStoreSession>>>::from_ref(state);
        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|_| AuthRedirect)?;

        // Get session from cookie
        let session_cookie = cookies
            .get(engine::SESSION_COOKIE_NAME)
            .ok_or(AuthRedirect)?;
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

impl<S> OptionalFromRequestParts<S> for User
where
    Arc<Mutex<Box<dyn crate::storage::CacheStoreSession>>>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        match <User as FromRequestParts<S>>::from_request_parts(parts, state).await {
            Ok(res) => Ok(Some(res)),
            Err(AuthRedirect) => Ok(None),
        }
    }
}
