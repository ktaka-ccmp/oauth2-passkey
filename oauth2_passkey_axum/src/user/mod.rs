mod default;
#[cfg(feature = "user-ui")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    #[cfg(feature = "user-ui")]
    {
        default::router().merge(optional::router())
    }
    #[cfg(not(feature = "user-ui"))]
    {
        default::router()
    }
}
