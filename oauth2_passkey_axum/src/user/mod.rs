mod default;
#[cfg(feature = "user-ui")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    let mut router = default::router();
    #[cfg(feature = "user-ui")]
    {
        router = router.merge(optional::router());
    }
    router
}
