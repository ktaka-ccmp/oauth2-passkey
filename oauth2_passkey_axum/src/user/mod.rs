mod default;
#[cfg(feature = "user-ui")]
mod optional;

use axum::Router;

use super::login_history;

pub(super) fn router() -> Router {
    let base = default::router().merge(login_history::user_router());

    #[cfg(feature = "user-ui")]
    {
        base.merge(optional::router())
    }
    #[cfg(not(feature = "user-ui"))]
    {
        base
    }
}
