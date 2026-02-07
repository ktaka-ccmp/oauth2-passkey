use askama::Template;
use axum::{
    http::StatusCode,
    response::Html,
    routing::{Router, get},
};
use axum_core::response::IntoResponse;
use dotenvy::dotenv;

use oauth2_passkey_axum::{AuthUser, O2P_ROUTE_PREFIX, oauth2_passkey_full_router};

mod server;
use crate::server::{init_tracing, spawn_http_server};

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexAnonTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'static str,
}

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexUserTemplate<'a> {
    message: &'a str,
    o2p_route_prefix: &'static str,
}

async fn index(user: Option<AuthUser>) -> impl IntoResponse {
    match user {
        Some(u) => {
            let template = IndexUserTemplate {
                message: &format!("Hello, {}!", u.account),
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            (StatusCode::OK, Html(template.render().unwrap())).into_response()
        }
        None => {
            let template = IndexAnonTemplate {
                message: "Hello, anonymous user",
                o2p_route_prefix: O2P_ROUTE_PREFIX.as_str(),
            };
            (StatusCode::OK, Html(template.render().unwrap())).into_response()
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing("demo_passkey");

    dotenv().ok();
    oauth2_passkey_axum::init().await?;

    let app = Router::new()
        .route("/", get(index))
        .merge(oauth2_passkey_full_router());

    spawn_http_server(3001, app).await?;
    Ok(())
}
