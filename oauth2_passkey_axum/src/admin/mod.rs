mod default;
#[cfg(feature = "admin-ui")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    #[cfg(feature = "admin-ui")]
    {
        default::router().merge(optional::router())
    }
    #[cfg(not(feature = "admin-ui"))]
    {
        default::router()
    }
}
