//! User database module for managing user accounts.
//!
//! This module provides functionality for storing, retrieving, updating, and
//! deleting user accounts in the database. It handles the persistence of user
//! account information, separate from authentication methods like OAuth2 or
//! passkeys, which are linked to these user accounts.
//!
//! The module abstracts the database operations through a storage layer,
//! allowing for different database backends.

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
