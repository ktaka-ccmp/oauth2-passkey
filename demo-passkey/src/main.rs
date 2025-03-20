use askama::Template;
use axum::{
    http::StatusCode,
    response::Html,
    routing::{Router, get},
};
use axum_core::response::IntoResponse;

use libaxum::passkey_router;
use oauth2_passkey::{PASSKEY_ROUTE_PREFIX, passkey_init};

mod routes;

#[derive(Template)]
#[template(path = "index.j2")]
struct IndexTemplate {
    passkey_route_prefix: &'static str,
}

async fn index() -> impl IntoResponse {
    let template = IndexTemplate {
        passkey_route_prefix: PASSKEY_ROUTE_PREFIX.as_str(),
    };
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    passkey_init().await?;

    let app = Router::new()
        .route("/", get(index))
        .nest("/auth", routes::router_auth())
        .nest("/register", routes::router_register())
        .nest(PASSKEY_ROUTE_PREFIX.as_str(), passkey_router());

    println!("Starting server on http://localhost:3001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
