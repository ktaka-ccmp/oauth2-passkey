use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect},
};

// Simple authentication checker
pub async fn is_authenticated_or_error(req: Request, next: Next) -> impl IntoResponse {
    match oauth2_passkey::is_authenticated_basic(req.headers()).await {
        Ok(true) => next.run(req).await,
        Ok(false) | Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    }
}

// Authentication checker with custom redirect URL
pub async fn is_authenticated_or_redirect(
    redirect_url: Option<&'static str>,
    req: Request,
    next: Next,
) -> impl IntoResponse {
    match oauth2_passkey::is_authenticated_basic(req.headers()).await {
        Ok(true) => next.run(req).await,
        Ok(false) | Err(_) => match redirect_url {
            Some(url) => Redirect::temporary(url).into_response(),
            None => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
        },
    }
}

// Authentication check with user retrieval.
// Pass the user to next handler
pub async fn is_authenticated_with_user(
    user: Option<super::session::AuthUser>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    match user {
        Some(user) => {
            tracing::debug!("User: {:?}", user);
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    }
}
