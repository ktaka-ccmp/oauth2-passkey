//! Provider icon routes
//!
//! Serves branded SVG icons for OAuth2 providers at
//! `{O2P_ROUTE_PREFIX}/icons/<name>.svg`. Provider marks (Google,
//! Microsoft, Auth0, Keycloak) are sourced from svgl
//! (<https://svgl.app/>); the neutral OpenID fallback and the Okta /
//! Authentik marks are from Simple Icons (<https://simpleicons.org/>,
//! CC0). The Zitadel mark is from the upstream Zitadel repository
//! (Apache-2.0). Brand trademarks remain with the respective owners;
//! usage here is nominative (identifying a linked account).

use axum::{
    Router,
    http::{
        StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::Response,
    routing::get,
};

pub(crate) fn router() -> Router<()> {
    Router::new()
        .route("/google.svg", get(serve_google))
        .route("/auth0.svg", get(serve_auth0))
        .route("/keycloak.svg", get(serve_keycloak))
        .route("/entra.svg", get(serve_entra))
        .route("/zitadel.svg", get(serve_zitadel))
        .route("/okta.svg", get(serve_okta))
        .route("/authentik.svg", get(serve_authentik))
        .route("/openid.svg", get(serve_openid))
}

fn svg_response(content: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "image/svg+xml")
        .header(CACHE_CONTROL, "public, max-age=604800, immutable")
        .body(content.into())
        .expect("static SVG response is always buildable")
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

async fn serve_zitadel() -> Response {
    svg_response(include_str!("../static/icons/zitadel.svg"))
}

async fn serve_okta() -> Response {
    svg_response(include_str!("../static/icons/okta.svg"))
}

async fn serve_authentik() -> Response {
    svg_response(include_str!("../static/icons/authentik.svg"))
}

async fn serve_openid() -> Response {
    svg_response(include_str!("../static/icons/openid.svg"))
}
