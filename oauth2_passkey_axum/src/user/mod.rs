#[cfg(feature = "user-ui")]
mod account;
mod default;
#[cfg(feature = "login-ui")]
mod login;

use axum::Router;

use super::login_history;

pub(super) fn router() -> Router {
    #[allow(unused_mut)]
    let mut base = default::router().merge(login_history::user_router());

    #[cfg(feature = "login-ui")]
    {
        base = base.merge(login::router());
    }

    #[cfg(feature = "user-ui")]
    {
        base = base.merge(account::router());
    }

    base
}
