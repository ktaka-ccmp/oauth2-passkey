use axum::routing::{Router, delete, get, post};

use super::handlers::{
    conditional_ui, delete_passkey_credential, handle_finish_authentication,
    handle_finish_registration, handle_start_authentication, handle_start_registration_post,
    list_passkey_credentials, serve_conditional_ui_js, serve_passkey_js, serve_related_origin,
};

pub fn router() -> Router {
    Router::new()
        .route("/passkey.js", get(serve_passkey_js))
        .route("/conditional_ui", get(conditional_ui))
        .route("/conditional_ui.js", get(serve_conditional_ui_js))
        .nest("/auth", router_auth())
        .nest("/register", router_register())
        .route("/credentials", get(list_passkey_credentials))
        .route(
            "/credentials/{credential_id}",
            delete(delete_passkey_credential),
        )
}

pub fn router_register() -> Router {
    Router::new()
        .route("/start", post(handle_start_registration_post))
        .route("/finish", post(handle_finish_registration))
}

pub fn router_auth() -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
}

/// Creates a router for the WebAuthn well-known endpoint
/// This should be mounted at the root level of the application
pub fn passkey_well_known_router() -> Router {
    Router::new().route("/webauthn", get(serve_related_origin))
}
