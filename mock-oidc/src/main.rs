//! Standalone mock OIDC provider used by the Playwright E2E suite.
//!
//! All real logic lives in the `mock-oidc-core` library crate; this binary
//! parses env vars, builds an `AppState`, and serves the router.
//!
//! Environment variables:
//! - `MOCK_OIDC_BIND` (default `127.0.0.1:9876`)
//! - `MOCK_OIDC_ISSUER` (default `http://{bind}`)
//! - `MOCK_OIDC_CLIENT_ID` (default `test-client-id.apps.googleusercontent.com`)
//! - `MOCK_OIDC_USER_{EMAIL,SUB,NAME,GIVEN_NAME,FAMILY_NAME}` to override
//!   the default `TestUser`

use mock_oidc_core::{AppState, TestUser, build_router, test_routes};
use std::{env, time::Duration};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let bind = env::var("MOCK_OIDC_BIND").unwrap_or_else(|_| "127.0.0.1:9876".to_string());
    let issuer = env::var("MOCK_OIDC_ISSUER").unwrap_or_else(|_| format!("http://{bind}"));
    let client_id = env::var("MOCK_OIDC_CLIENT_ID")
        .unwrap_or_else(|_| "test-client-id.apps.googleusercontent.com".to_string());

    let mut user = TestUser::default_first_user();
    if let Ok(v) = env::var("MOCK_OIDC_USER_EMAIL") {
        user.email = v;
    }
    if let Ok(v) = env::var("MOCK_OIDC_USER_SUB") {
        user.sub = v;
    }
    if let Ok(v) = env::var("MOCK_OIDC_USER_NAME") {
        user.name = v;
    }
    if let Ok(v) = env::var("MOCK_OIDC_USER_GIVEN_NAME") {
        user.given_name = v;
    }
    if let Ok(v) = env::var("MOCK_OIDC_USER_FAMILY_NAME") {
        user.family_name = v;
    }

    let state = AppState::new(issuer.clone(), client_id.clone(), user);

    let cleanup_state = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            cleanup_state.cleanup_expired_codes();
        }
    });

    let app = build_router(state.clone()).merge(test_routes(state));

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {bind}: {e}"));

    tracing::info!(
        issuer = %issuer,
        client_id = %client_id,
        bind = %bind,
        "mock-oidc listening"
    );

    axum::serve(listener, app).await.expect("server error");
}
