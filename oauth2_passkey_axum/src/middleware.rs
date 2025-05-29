use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use http::header::HeaderValue;

use super::config::{O2P_REDIRECT_ANON, O2P_RESPOND_WITH_X_CSRF_TOKEN};
use super::session::AuthUser;
use oauth2_passkey::SessionError;

// Helper function to add CSRF token to response
fn add_csrf_header(mut response: Response, csrf_token: &str) -> Response {
    if !*O2P_RESPOND_WITH_X_CSRF_TOKEN {
        return response;
    }

    // Use from_str with error handling instead of unwrap
    if let Ok(header_value) = HeaderValue::from_str(csrf_token) {
        response.headers_mut().insert("X-CSRF-Token", header_value);
    } else {
        // Log the error but don't panic
        tracing::error!("Failed to create CSRF header value from token");
    }
    response
}

// Helper function to handle authentication errors
fn handle_auth_error(err: SessionError, req: &Request, redirect_on_error: bool) -> Response {
    match err {
        SessionError::CsrfToken(msg) => {
            // For CSRF errors, return 403 Forbidden with the message
            // For redirect middleware with GET requests, redirect instead
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
            } else {
                (StatusCode::FORBIDDEN, msg).into_response()
            }
        }
        _ => {
            // For other authentication errors
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_REDIRECT_ANON.as_str()).into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
        }
    }
}

// Authentication checker with 401 response
pub async fn is_authenticated_401(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_csrf(req.headers(), req.method()).await {
        Ok((csrf_token, csrf_via_header_verified)) => {
            // Store token and verification status in extensions
            req.extensions_mut().insert(csrf_token.clone());
            req.extensions_mut().insert(csrf_via_header_verified);
            // Run next handler and add CSRF header to the response
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, false),
    }
}

// Authentication checker with redirect
pub async fn is_authenticated_redirect(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_csrf(req.headers(), req.method()).await {
        Ok((csrf_token, csrf_via_header_verified)) => {
            // Store token and verification status in extensions
            req.extensions_mut().insert(csrf_token.clone());
            req.extensions_mut().insert(csrf_via_header_verified);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, true),
    }
}

// Authentication check with user retrieval and 401 response
pub async fn is_authenticated_user_401(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_user_and_csrf(req.headers(), req.method())
        .await
    {
        Ok((user, csrf_token, csrf_via_header_verified)) => {
            let mut auth_user = AuthUser::from(user);
            auth_user.csrf_token = csrf_token.as_str().to_string();
            auth_user.csrf_via_header_verified = csrf_via_header_verified.0; // Set this field
            tracing::debug!(
                "User: {:?}, CSRF via header: {}",
                auth_user,
                csrf_via_header_verified
            );
            req.extensions_mut().insert(auth_user);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, false),
    }
}

// Authentication check with user retrieval and redirect
pub async fn is_authenticated_user_redirect(mut req: Request, next: Next) -> Response {
    match oauth2_passkey::is_authenticated_basic_then_user_and_csrf(req.headers(), req.method())
        .await
    {
        Ok((user, csrf_token, csrf_via_header_verified)) => {
            let mut auth_user = AuthUser::from(user);
            auth_user.csrf_token = csrf_token.as_str().to_string();
            auth_user.csrf_via_header_verified = csrf_via_header_verified.0; // Set this field
            tracing::debug!(
                "User: {:?}, CSRF via header: {}",
                auth_user,
                csrf_via_header_verified
            );
            req.extensions_mut().insert(auth_user);
            let response = next.run(req).await;
            add_csrf_header(response, csrf_token.as_str())
        }
        Err(err) => handle_auth_error(err, &req, true),
    }
}
