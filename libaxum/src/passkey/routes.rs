use axum::routing::{Router, get, post};

use super::handlers::{
    conditional_ui, handle_finish_authentication, handle_finish_registration,
    handle_start_authentication, handle_start_registration, handle_start_registration_get, index,
    serve_conditional_ui_js, serve_passkey_js,
};

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/passkey.js", get(serve_passkey_js))
        .route("/conditional_ui", get(conditional_ui))
        .route("/conditional_ui.js", get(serve_conditional_ui_js))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
}

pub fn router_register() -> Router {
    Router::new()
        .route(
            "/start",
            post(handle_start_registration).get(handle_start_registration_get),
        )
        .route("/finish", post(handle_finish_registration))
}

pub fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}
