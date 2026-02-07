mod default;
#[cfg(feature = "admin-ui")]
mod optional;

use axum::Router;

use super::login_history;

pub(super) fn router() -> Router {
    let base = default::router().merge(login_history::admin_router());

    #[cfg(feature = "admin-ui")]
    {
        base.merge(optional::router())
    }
    #[cfg(not(feature = "admin-ui"))]
    {
        base
    }
}
