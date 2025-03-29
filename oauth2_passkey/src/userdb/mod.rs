mod errors;
mod storage;
mod types;

pub use errors::UserError;
pub(crate) use storage::DB_TABLE_USERS;
pub use storage::UserStore;
pub use types::User;

pub async fn init() -> Result<(), UserError> {
    UserStore::init().await
}
