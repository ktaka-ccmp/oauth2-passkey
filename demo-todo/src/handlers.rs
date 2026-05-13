use axum::{
    Extension, Form, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware::from_fn,
    response::{IntoResponse, Redirect, Response},
    routing::post,
};
use oauth2_passkey_axum::{AuthUser, CsrfHeaderVerified, CsrfToken, is_authenticated_redirect};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::db;

#[derive(Deserialize)]
pub struct CreateTodoForm {
    title: String,
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct ActionForm {
    csrf_token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/todos", post(create_todo))
        .route("/todos/{id}/toggle", post(toggle_todo))
        .route("/todos/{id}/delete", post(delete_todo))
        .route_layer(from_fn(is_authenticated_redirect))
}

/// Verify CSRF token for form submission
fn verify_csrf(form_token: &str, csrf_token: &CsrfToken, header_verified: bool) -> bool {
    if header_verified {
        return true;
    }
    form_token
        .as_bytes()
        .ct_eq(csrf_token.as_str().as_bytes())
        .into()
}

/// Create a new todo
async fn create_todo(
    State(state): State<AppState>,
    user: AuthUser,
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_header_verified): Extension<CsrfHeaderVerified>,
    Form(form): Form<CreateTodoForm>,
) -> Result<Response, (StatusCode, String)> {
    if !verify_csrf(&form.csrf_token, &csrf_token, csrf_header_verified.0) {
        return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Title cannot be empty".to_string()));
    }

    db::create_todo(&state.pool, &user.id, title)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create todo: {e}"),
            )
        })?;

    Ok(Redirect::to("/").into_response())
}

/// Toggle todo completion status
async fn toggle_todo(
    State(state): State<AppState>,
    user: AuthUser,
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_header_verified): Extension<CsrfHeaderVerified>,
    Path(id): Path<i64>,
    Form(form): Form<ActionForm>,
) -> Result<Response, (StatusCode, String)> {
    if !verify_csrf(&form.csrf_token, &csrf_token, csrf_header_verified.0) {
        return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
    }

    db::toggle_todo(&state.pool, id, &user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to toggle todo: {e}"),
            )
        })?;

    Ok(Redirect::to("/").into_response())
}

/// Delete a todo
async fn delete_todo(
    State(state): State<AppState>,
    user: AuthUser,
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_header_verified): Extension<CsrfHeaderVerified>,
    Path(id): Path<i64>,
    Form(form): Form<ActionForm>,
) -> Result<Response, (StatusCode, String)> {
    if !verify_csrf(&form.csrf_token, &csrf_token, csrf_header_verified.0) {
        return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
    }

    db::delete_todo(&state.pool, id, &user.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to delete todo: {e}"),
            )
        })?;

    Ok(Redirect::to("/").into_response())
}
