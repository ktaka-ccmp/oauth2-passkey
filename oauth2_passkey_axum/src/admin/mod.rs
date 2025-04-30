mod default;
#[cfg(feature = "admin-ui")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    let mut router = default::router();
    #[cfg(feature = "admin-ui")]
    {
        router = router.merge(optional::router());
    }
    router
}
