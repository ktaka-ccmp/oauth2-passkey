use askama::Template;
use axum::{
    Extension, Form, Router,
    extract::State,
    http::StatusCode,
    middleware::from_fn,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use oauth2_passkey_axum::{
    AuthUser, CsrfHeaderVerified, CsrfToken, UserId, is_authenticated_redirect, list_accounts_core,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::db::{self, UserProfile};

#[derive(Template)]
#[template(path = "profile.j2")]
struct ProfileTemplate {
    user: TemplateUser,
    profile: UserProfile,
    csrf_token: String,
}

struct TemplateUser {
    user_id: String,
    label: String,
    account: String,
}

#[derive(Deserialize)]
pub struct ProfileForm {
    display_name: Option<String>,
    bio: Option<String>,
    avatar_url: Option<String>,
    theme: String,
    csrf_token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/profile", get(show_profile).post(update_profile))
        .route_layer(from_fn(is_authenticated_redirect))
}

/// Show profile page - uses AuthUser extractor directly
async fn show_profile(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Response, (StatusCode, String)> {
    // Try to get existing profile
    let profile = match db::get_profile(&state.pool, &user.id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            // Profile doesn't exist, create one with Google avatar if available
            let avatar_url = get_google_avatar(&user.id).await;
            db::create_profile_with_avatar(&state.pool, &user.id, avatar_url)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to create profile: {e}"),
                    )
                })?
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {e}"),
            ));
        }
    };

    let template = ProfileTemplate {
        user: TemplateUser {
            user_id: user.id.clone(),
            label: user.label.clone(),
            account: user.account.clone(),
        },
        profile,
        csrf_token: user.csrf_token.clone(),
    };

    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Update profile - uses middleware-provided CsrfToken for form validation
async fn update_profile(
    State(state): State<AppState>,
    user: AuthUser,
    Extension(csrf_token): Extension<CsrfToken>,
    Extension(csrf_header_verified): Extension<CsrfHeaderVerified>,
    Form(form): Form<ProfileForm>,
) -> Result<Response, (StatusCode, String)> {
    // Verify CSRF token for form submission
    if !csrf_header_verified.0 {
        let is_valid: bool = form
            .csrf_token
            .as_bytes()
            .ct_eq(csrf_token.as_str().as_bytes())
            .into();
        if !is_valid {
            return Err((StatusCode::FORBIDDEN, "Invalid CSRF token".to_string()));
        }
    }

    let profile = UserProfile {
        user_id: user.id.clone(),
        display_name: form.display_name.filter(|s| !s.trim().is_empty()),
        bio: form.bio.filter(|s| !s.trim().is_empty()),
        avatar_url: form.avatar_url.filter(|s| !s.trim().is_empty()),
        theme: form.theme,
        ..Default::default()
    };

    db::upsert_profile(&state.pool, &profile)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to update profile: {e}"),
            )
        })?;

    Ok(Redirect::to("/").into_response())
}

/// Get Google avatar URL from OAuth2 accounts
async fn get_google_avatar(user_id: &str) -> Option<String> {
    let user_id = UserId::new(user_id.to_string()).ok()?;
    let accounts = list_accounts_core(user_id).await.ok()?;

    accounts
        .into_iter()
        .find(|a| a.provider == "google")
        .and_then(|a| a.picture)
}
