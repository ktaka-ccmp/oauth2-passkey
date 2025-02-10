use axum::response::{IntoResponse, Redirect, Response};

#[derive(Clone, Default)]
pub(crate) struct AppState {}

pub(crate) struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/").into_response()
    }
}
