use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::{TypedHeader, headers};
use serde::Deserialize;

use oauth2_passkey::prepare_logout_response;

#[derive(Deserialize)]
pub(super) struct RedirectQuery {
    redirect: Option<String>,
}

/// Handles logout requests with optional redirection
///
/// If no redirect parameter is provided in the query string, this function
/// will just return the logout headers. If a redirect parameter is provided,
/// it will redirect to that URL after clearing the session.
pub(super) async fn logout(
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    Query(params): Query<RedirectQuery>,
) -> impl IntoResponse {
    // Clear the session and handle errors
    match prepare_logout_response(cookies).await {
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Ok(headers) => match params.redirect {
            Some(redirect_to) => {
                // Redirect to the specified URL
                tracing::debug!("Redirecting to {}", redirect_to);
                (headers, Redirect::to(&redirect_to)).into_response()
            }
            None => {
                // Just return the headers (for API/AJAX calls)
                tracing::debug!("No redirect specified, returning headers");
                (headers, StatusCode::OK).into_response()
            }
        },
    }
}
