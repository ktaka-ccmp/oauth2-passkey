use std::{env, sync::LazyLock};

use crate::storage::DB_TABLE_PREFIX;

/// Users table name
pub(crate) static DB_TABLE_USERS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_USERS").unwrap_or_else(|_| format!("{}{}", *DB_TABLE_PREFIX, "users"))
});
