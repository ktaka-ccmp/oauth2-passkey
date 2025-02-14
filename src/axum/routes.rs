use axum::routing::{get, post, Router};

use super::handlers::{
    handle_finish_authentication, handle_finish_registration, handle_start_authentication,
    handle_start_registration, index,
};
use crate::types::AppState;

pub fn router(passkey_state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .nest("/auth", router_auth(passkey_state.clone()))
        .nest("/register", router_register(passkey_state))
}

pub fn router_register(state: AppState) -> Router {
    Router::new()
        .route("/start", post(handle_start_registration))
        .route("/finish", post(handle_finish_registration))
        .with_state(state)
}

pub fn router_auth(state: AppState) -> Router {
    Router::new()
        .route("/start", post(handle_start_authentication))
        .route("/finish", post(handle_finish_authentication))
        .with_state(state)
}
