mod errors;
mod storage;
mod types;

pub(crate) use errors::UserError;
pub(crate) use storage::DB_TABLE_USERS;
pub(crate) use storage::UserStore;
pub use types::User;

pub(crate) async fn init() -> Result<(), UserError> {
    UserStore::init().await
}
