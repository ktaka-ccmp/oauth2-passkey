use askama::Template;
use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use dotenvy::dotenv;
use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX, oauth2_passkey_full_router};
use sqlx::PgPool;

mod db;
mod handlers;
mod server;

use server::{init_tracing, spawn_http_server, spawn_https_server};

/// Application state - shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    user: Option<TemplateUser<'a>>,
    prefix: &'a str,
}

struct TemplateUser<'a> {
    label: &'a str,
    display_name: Option<String>,
    bio: Option<String>,
    avatar_url: Option<String>,
}

/// Home page - shows user info if logged in, otherwise login prompt
async fn index(
    State(state): State<AppState>,
    user: Option<AuthUser>,
) -> Result<Response, (StatusCode, String)> {
    let template_user = match user {
        Some(ref u) => {
            // Get profile data if exists
            let profile = db::get_profile(&state.pool, &u.id).await.ok().flatten();

            Some(TemplateUser {
                label: &u.label,
                display_name: profile.as_ref().and_then(|p| p.display_name.clone()),
                bio: profile.as_ref().and_then(|p| p.bio.clone()),
                avatar_url: profile.and_then(|p| p.avatar_url),
            })
        }
        None => None,
    };

    let template = IndexTemplate {
        user: template_user,
        prefix: O2P_ROUTE_PREFIX.as_str(),
    };

    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    init_tracing("demo-profile");

    dotenv().ok();

    // Initialize oauth2-passkey library
    oauth2_passkey_axum::init().await?;

    // Initialize profile database and create app state
    let pool = db::init_db().await?;
    let state = AppState { pool };

    // Routes that use our AppState
    let app_routes = Router::new()
        .route("/", get(index))
        .merge(handlers::router())
        .with_state(state);

    // Combine with oauth2-passkey routes
    let app = app_routes.merge(oauth2_passkey_full_router());

    let http_server = spawn_http_server(3001, app.clone());
    let https_server = spawn_https_server(3443, app).await;

    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
