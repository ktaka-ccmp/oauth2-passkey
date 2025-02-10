use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use libsession::{SessionState, User};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) session_state: SessionState,
}

pub(crate) struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}

// Extract SessionState from AppState for User extractor
impl FromRequestParts<AppState> for User {
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        User::from_request_parts(parts, &state.session_state)
            .await
            .map_err(|_| AuthRedirect)
    }
}

// Extract SessionState from AppState for Option<User> extractor
impl FromRequestParts<AppState> for Option<User> {
    type Rejection = (axum::http::StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Option::<User>::from_request_parts(parts, &state.session_state)
            .await
            .map_err(|_| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            })
    }
}
