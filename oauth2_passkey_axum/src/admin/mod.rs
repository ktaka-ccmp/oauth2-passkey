mod default;
#[cfg(feature = "admin-pages")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    let mut router = default::router();
    #[cfg(feature = "admin-pages")]
    {
        router = router.merge(optional::router());
    }
    router
}
