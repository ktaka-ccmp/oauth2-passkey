//! Theme CSS routes for pre-built UI themes
//!
//! Provides optional CSS theme files that can be loaded via `O2P_CUSTOM_CSS_URL`
//! to customize the appearance of authentication pages.
//!
//! Themes are served at `{O2P_ROUTE_PREFIX}/themes/<theme-name>.css`.

use axum::{
    Router,
    http::{StatusCode, header::CONTENT_TYPE},
    response::Response,
    routing::get,
};

pub(crate) fn router() -> Router<()> {
    Router::new()
        .route("/theme-zinc.css", get(serve_theme_zinc))
        .route("/theme-slate.css", get(serve_theme_slate))
        .route("/theme-blue.css", get(serve_theme_blue))
        .route("/theme-violet.css", get(serve_theme_violet))
        .route("/theme-rose.css", get(serve_theme_rose))
        .route("/theme-neumorphism.css", get(serve_theme_neumorphism))
        .route("/theme-material.css", get(serve_theme_material))
        .route("/theme-eco.css", get(serve_theme_eco))
        .route("/theme-saas.css", get(serve_theme_saas))
}

fn css_response(content: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css")
        .body(content.into())
        .unwrap_or_else(|_| Response::new("Failed to build response".into()))
}

async fn serve_theme_zinc() -> Response {
    css_response(include_str!("../static/theme-zinc.css"))
}

async fn serve_theme_slate() -> Response {
    css_response(include_str!("../static/theme-slate.css"))
}

async fn serve_theme_blue() -> Response {
    css_response(include_str!("../static/theme-blue.css"))
}

async fn serve_theme_violet() -> Response {
    css_response(include_str!("../static/theme-violet.css"))
}

async fn serve_theme_rose() -> Response {
    css_response(include_str!("../static/theme-rose.css"))
}

async fn serve_theme_neumorphism() -> Response {
    css_response(include_str!("../static/theme-neumorphism.css"))
}

async fn serve_theme_material() -> Response {
    css_response(include_str!("../static/theme-material.css"))
}

async fn serve_theme_eco() -> Response {
    css_response(include_str!("../static/theme-eco.css"))
}

async fn serve_theme_saas() -> Response {
    css_response(include_str!("../static/theme-saas.css"))
}
