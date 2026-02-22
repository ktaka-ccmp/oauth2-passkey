use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use http::header::HeaderValue;

use super::config::{O2P_LOGIN_URL, O2P_RESPOND_WITH_X_CSRF_TOKEN};
use super::session::AuthUser;
use oauth2_passkey::SessionError;

/// Helper function to add CSRF token to response headers
///
/// Adds the CSRF token as an X-CSRF-Token header to the response
/// if O2P_RESPOND_WITH_X_CSRF_TOKEN is enabled.
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

/// Helper function to handle authentication errors
///
/// Processes
///  authentication errors and returns appropriate responses:
/// - For CSRF errors: returns 403 Forbidden or redirects if redirect_on_error is true
/// - For other auth errors: returns 401 Unauthorized or redirects if redirect_on_error is true
fn handle_auth_error(err: SessionError, req: &Request, redirect_on_error: bool) -> Response {
    match err {
        SessionError::CsrfToken(msg) => {
            // For CSRF errors, return 403 Forbidden with the message
            // For redirect middleware with GET requests, redirect instead
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_LOGIN_URL.as_str()).into_response()
            } else {
                (StatusCode::FORBIDDEN, msg).into_response()
            }
        }
        _ => {
            // For other authentication errors
            if redirect_on_error && req.method() == http::Method::GET {
                Redirect::temporary(O2P_LOGIN_URL.as_str()).into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
        }
    }
}

/// Authentication middleware that returns HTTP 401 for unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Returns 401 Unauthorized for unauthenticated requests
/// 4. Adds the CSRF token to the response headers
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn};
/// use oauth2_passkey_axum::is_authenticated_401;
///
/// # async fn handler() -> &'static str { "Hello" }
/// let app: Router = Router::new()
///     .route("/api/data", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_401));
/// ```
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

/// Authentication middleware that redirects unauthenticated requests to login page
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Redirects unauthenticated GET requests to the login URL (as defined in O2P_LOGIN_URL)
/// 4. Returns 401 for unauthenticated non-GET requests
/// 5. Adds the CSRF token to the response headers
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn};
/// use oauth2_passkey_axum::is_authenticated_redirect;
///
/// # async fn handler() -> &'static str { "Hello" }
/// let app: Router = Router::new()
///     .route("/dashboard", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_redirect));
/// ```
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

/// Authentication middleware that provides user data and returns HTTP 401 for unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Extracts user data from the session and adds it as an extension
/// 4. Returns 401 Unauthorized for unauthenticated requests
/// 5. Adds the CSRF token to the response headers
///
/// This version adds the authenticated user information as an `Extension<AuthUser>`,
/// which can be accessed in handlers.
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn, extract::Extension};
/// use oauth2_passkey_axum::{is_authenticated_user_401, AuthUser};
///
/// async fn handler(Extension(user): Extension<AuthUser>) -> String {
///     format!("Hello, {}", user.account)
/// }
///
/// let app: Router = Router::new()
///     .route("/api/profile", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_user_401));
/// ```
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

/// Authentication middleware that provides user data and redirects unauthenticated requests
///
/// This middleware:
/// 1. Verifies that the request has a valid session cookie
/// 2. For state-changing methods (POST, PUT, DELETE, PATCH), verifies CSRF protection
/// 3. Extracts user data from the session and adds it as an extension
/// 4. Redirects unauthenticated GET requests to the login page
/// 5. Returns 401 for unauthenticated non-GET requests
/// 6. Adds the CSRF token to the response headers
///
/// This version adds the authenticated user information as an `Extension<AuthUser>`,
/// which can be accessed in handlers.
///
/// # Example
/// ```no_run
/// use axum::{Router, middleware::from_fn, extract::Extension};
/// use oauth2_passkey_axum::{is_authenticated_user_redirect, AuthUser};
///
/// async fn handler(Extension(user): Extension<AuthUser>) -> String {
///     format!("Hello, {}", user.account)
/// }
///
/// let app: Router = Router::new()
///     .route("/dashboard", axum::routing::get(handler))
///     .layer(from_fn(is_authenticated_user_redirect));
/// ```
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

#[cfg(test)]
mod tests;
