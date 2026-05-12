use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};

use dotenvy::dotenv;

use oauth2_passkey_axum::{
    AuthUser, O2P_CUSTOM_CSS_URL, O2P_ROUTE_PREFIX, oauth2_passkey_full_router,
    reset_storage_for_test, spawn_login_history_cleanup,
};

mod protected;
mod server;
use askama::Template;
use axum::response::Html;
use server::{init_tracing, spawn_http_server};

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate<'a> {
    message: &'a str,
    prefix: &'a str,
    custom_css_url: Option<&'a str>,
}

async fn test_reset() -> Result<StatusCode, (StatusCode, String)> {
    reset_storage_for_test()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
}

// AuthUser extractor redirects unauthenticated users to O2P_LOGIN_URL automatically
async fn index(_user: AuthUser) -> Result<Response, (StatusCode, String)> {
    let template = IndexTemplate {
        message: "This is a protected page.",
        prefix: O2P_ROUTE_PREFIX.as_str(),
        custom_css_url: O2P_CUSTOM_CSS_URL.as_deref(),
    };
    match template.render() {
        Ok(html) => Ok(Html(html).into_response()),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo-both");

    // Skip .env loading when invoked from automated tests so the user's
    // workspace-root .env does not leak into the test environment.
    if std::env::var("DEMO_BOTH_SKIP_DOTENV").is_err() {
        dotenv().ok();
    }
    oauth2_passkey_axum::init().await?;

    spawn_login_history_cleanup();

    let mut app = Router::new()
        .route("/", get(index))
        .merge(oauth2_passkey_full_router())
        .merge(protected::router());

    // E2E test harness: when DEMO_BOTH_TEST_RESET=1, expose POST /test/reset
    // for Playwright fixtures to wipe persistent state between tests.
    if std::env::var("DEMO_BOTH_TEST_RESET").is_ok() {
        app = app.route("/test/reset", post(test_reset));
        tracing::warn!("DEMO_BOTH_TEST_RESET enabled — mounting POST /test/reset");
    }

    let port = std::env::var("DEMO_BOTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3001);
    spawn_http_server(port, app).await?;
    Ok(())
}
