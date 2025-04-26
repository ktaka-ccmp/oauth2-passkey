mod default;
#[cfg(feature = "optional-pages")]
mod optional;

use axum::Router;

pub(super) fn router() -> Router {
    let mut router = default::router();
    #[cfg(feature = "optional-pages")]
    {
        router = router.merge(optional::router());
    }
    router
}
