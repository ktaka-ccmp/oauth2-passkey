//! Demo API application demonstrating Bearer token authentication.
//!
//! This API-only demo shows how to use Bearer token authentication mode
//! for API/mobile clients with passkey authentication.
//!
//! Run with: SESSION_AUTH_MODE=bearer cargo run

use axum::{
    Json, Router,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oauth2_passkey::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    RegistrationStartRequest, SessionCreationResponse, SessionUser,
    handle_finish_authentication_core, handle_finish_registration_core,
    handle_start_authentication_core, handle_start_registration_core, is_authenticated_basic,
    is_authenticated_basic_then_user_and_csrf,
};

/// Bearer token response for successful authentication.
#[derive(Serialize)]
struct TokenResponse {
    token: String,
    token_type: String,
    expires_in: u64,
}

/// Error response format.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Protected resource response.
#[derive(Serialize)]
struct ProtectedResponse {
    message: String,
    user_id: String,
    account: String,
}

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    auth_mode: String,
}

// ============================================================================
// Health check endpoint
// ============================================================================

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        auth_mode: "bearer".to_string(),
    })
}

// ============================================================================
// Passkey Registration endpoints
// ============================================================================

async fn passkey_register_start(
    Json(request): Json<RegistrationStartRequest>,
) -> Result<Json<RegistrationOptions>, (StatusCode, Json<ErrorResponse>)> {
    // No authenticated user for initial registration
    let registration_options = handle_start_registration_core(None, request)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok(Json(registration_options))
}

async fn passkey_register_finish(
    Json(reg_data): Json<RegisterCredential>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // No authenticated user for initial registration
    let (session_response, _message) = handle_finish_registration_core(None, reg_data)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    // Return token based on session response type
    match session_response {
        SessionCreationResponse::Bearer {
            token,
            token_type,
            expires_in,
        } => Ok(Json(TokenResponse {
            token,
            token_type,
            expires_in,
        })
        .into_response()),
        SessionCreationResponse::Cookie(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Cookie mode not supported in API. Set SESSION_AUTH_MODE=bearer".to_string(),
            }),
        )),
        SessionCreationResponse::NoOp => {
            // This happens when adding credential to existing session
            Ok(Json(serde_json::json!({
                "message": "Credential registered successfully"
            }))
            .into_response())
        }
    }
}

// ============================================================================
// Passkey Authentication endpoints
// ============================================================================

#[derive(Deserialize, Serialize)]
struct AuthStartRequest {
    account: Option<String>,
}

async fn passkey_auth_start(
    Json(body): Json<AuthStartRequest>,
) -> Result<Json<AuthenticationOptions>, (StatusCode, Json<ErrorResponse>)> {
    let body_value = serde_json::to_value(body).unwrap_or(Value::Null);

    let auth_options = handle_start_authentication_core(&body_value)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    Ok(Json(auth_options))
}

async fn passkey_auth_finish(
    Json(auth_response): Json<AuthenticatorResponse>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let (_auth_data, session_response) = handle_finish_authentication_core(auth_response)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    // Return token based on session response type
    match session_response {
        SessionCreationResponse::Bearer {
            token,
            token_type,
            expires_in,
        } => Ok(Json(TokenResponse {
            token,
            token_type,
            expires_in,
        })
        .into_response()),
        SessionCreationResponse::Cookie(_) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Cookie mode not supported in API. Set SESSION_AUTH_MODE=bearer".to_string(),
            }),
        )),
        SessionCreationResponse::NoOp => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Unexpected NoOp response".to_string(),
            }),
        )),
    }
}

// ============================================================================
// Protected endpoints (require Bearer token)
// ============================================================================

async fn protected_resource(
    headers: HeaderMap,
) -> Result<Json<ProtectedResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Get user from session (handles Bearer token extraction internally)
    let (user, _csrf, _verified) =
        is_authenticated_basic_then_user_and_csrf(&headers, &http::Method::GET)
            .await
            .map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;

    Ok(Json(ProtectedResponse {
        message: "Access granted to protected resource".to_string(),
        user_id: user.id.clone(),
        account: user.account.clone(),
    }))
}

async fn me(headers: HeaderMap) -> Result<Json<SessionUser>, (StatusCode, Json<ErrorResponse>)> {
    // Get user from session (handles Bearer token extraction internally)
    let (user, _csrf, _verified) =
        is_authenticated_basic_then_user_and_csrf(&headers, &http::Method::GET)
            .await
            .map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;

    Ok(Json(user))
}

// ============================================================================
// Middleware for Bearer auth validation
// ============================================================================

async fn require_bearer_auth(
    request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let headers = request.headers();

    let status = is_authenticated_basic(headers, request.method())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;

    if !status.0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Bearer token required".to_string(),
            }),
        ));
    }

    Ok(next.run(request).await)
}

// ============================================================================
// Main
// ============================================================================

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        #[cfg(debug_assertions)]
        {
            "oauth2_passkey=debug,demo_api=debug".into()
        }
        #[cfg(not(debug_assertions))]
        {
            "info".into()
        }
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();
    dotenv().ok();

    // Verify SESSION_AUTH_MODE is set to bearer
    let auth_mode = std::env::var("SESSION_AUTH_MODE").unwrap_or_default();
    if auth_mode != "bearer" {
        tracing::warn!(
            "SESSION_AUTH_MODE is '{}', expected 'bearer' for API demo. \
             Set SESSION_AUTH_MODE=bearer in your .env file.",
            if auth_mode.is_empty() {
                "cookie (default)"
            } else {
                &auth_mode
            }
        );
    }

    oauth2_passkey::init().await?;

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/api/passkey/register/start", post(passkey_register_start))
        .route(
            "/api/passkey/register/finish",
            post(passkey_register_finish),
        )
        .route("/api/passkey/auth/start", post(passkey_auth_start))
        .route("/api/passkey/auth/finish", post(passkey_auth_finish));

    // Protected routes (require Bearer token)
    let protected_routes = Router::new()
        .route("/api/protected", get(protected_resource))
        .route("/api/me", get(me))
        .layer(middleware::from_fn(require_bearer_auth));

    let app = Router::new().merge(public_routes).merge(protected_routes);

    let addr = "0.0.0.0:3002";
    tracing::info!("Demo API server listening on http://{}", addr);
    tracing::info!("Try: curl http://localhost:3002/health");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
