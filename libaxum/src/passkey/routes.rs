use axum::routing::{Router, get, post};

use super::handlers::{
    conditional_ui, handle_finish_authentication, handle_finish_registration,
    handle_start_authentication, handle_start_registration_get, handle_start_registration_post,
    list_passkey_credentials, list_passkey_credentials_html, serve_conditional_ui_js,
    serve_passkey_js,
};

pub fn router() -> Router {
    Router::new()
        .route("/passkey.js", get(serve_passkey_js))
        .route("/conditional_ui", get(conditional_ui))
        .route("/conditional_ui.js", get(serve_conditional_ui_js))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
        .route("/credentials", get(list_passkey_credentials))
        .route("/credentials/html", get(list_passkey_credentials_html))
}

pub fn router_register() -> Router {
    Router::new()
        .route(
            "/start",
            post(handle_start_registration_post).get(handle_start_registration_get),
        )
        .route("/finish", post(handle_finish_registration))
}

pub fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}
