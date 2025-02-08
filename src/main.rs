use askama::Template;
use axum::{
    http::StatusCode,
    response::Html,
    routing::{get, Router},
};
use axum_core::response::IntoResponse;

mod routes;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

async fn index() -> impl IntoResponse {
    let template = IndexTemplate {};
    (StatusCode::OK, Html(template.render().unwrap())).into_response()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let passkey_state = libpasskey::AppState::new().await?;

    let app = Router::new()
        .route("/", get(index))
        .nest("/auth", routes::router_auth(passkey_state.clone()))
        .nest("/register", routes::router_register(passkey_state.clone()));

    println!("Starting server on http://localhost:3001");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
