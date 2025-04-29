use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect},
};

use super::config::O2P_REDIRECT_ANON;
use super::session::AuthUser;

// Authentication checker with custom redirect URL
pub async fn is_authenticated_401(req: Request, next: Next) -> impl IntoResponse {
    match oauth2_passkey::is_authenticated_basic(req.headers(), req.method()).await {
        Ok(true) => next.run(req).await,
        Ok(false) | Err(_) => (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    }
}

pub async fn is_authenticated_redirect(req: Request, next: Next) -> impl IntoResponse {
    match oauth2_passkey::is_authenticated_basic(req.headers(), req.method()).await {
        Ok(true) => next.run(req).await,
        Ok(false) | Err(_) => Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response(),
    }
}

// Authentication check with user retrieval.
// Pass the user to next handler
pub async fn is_authenticated_user_401(
    user: Option<AuthUser>,
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

pub async fn is_authenticated_user_redirect(
    user: Option<AuthUser>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    match user {
        Some(user) => {
            tracing::debug!("User: {:?}", user);
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response(),
    }
}
