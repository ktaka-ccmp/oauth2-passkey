//! Provider icon routes
//!
//! Serves branded SVG icons for OAuth2 providers at
//! `{O2P_ROUTE_PREFIX}/icons/<name>.svg`. Sourced from Simple Icons
//! (https://simpleicons.org/, CC0). Brand trademarks remain with the
//! respective owners; usage here is nominative (identifying a linked
//! account).

use axum::{
    Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::Response,
    routing::get,
};

pub(crate) fn router() -> Router<()> {
    Router::new()
        .route("/google.svg", get(serve_google))
        .route("/auth0.svg", get(serve_auth0))
        .route("/keycloak.svg", get(serve_keycloak))
        .route("/entra.svg", get(serve_entra))
        .route("/openid.svg", get(serve_openid))
}

fn svg_response(content: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/svg+xml")
        .body(content.into())
        .unwrap_or_else(|_| Response::new("Failed to build response".into()))
}

async fn serve_google() -> Response {
    svg_response(include_str!("../static/icons/google.svg"))
}

async fn serve_auth0() -> Response {
    svg_response(include_str!("../static/icons/auth0.svg"))
}

async fn serve_keycloak() -> Response {
    svg_response(include_str!("../static/icons/keycloak.svg"))
}

async fn serve_entra() -> Response {
    svg_response(include_str!("../static/icons/entra.svg"))
}

async fn serve_openid() -> Response {
    svg_response(include_str!("../static/icons/openid.svg"))
}
