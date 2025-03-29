mod errors;
mod types;
mod user;

pub use errors::UserError;
pub use types::User;
pub(crate) use user::DB_TABLE_USERS;
pub use user::UserStore;

pub async fn init() -> Result<(), UserError> {
    UserStore::init().await
}
