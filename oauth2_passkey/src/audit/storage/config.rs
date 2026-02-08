//! Configuration for login history table

use std::{env, sync::LazyLock};

use crate::storage::DB_TABLE_PREFIX;

/// Login history table name
pub(super) static DB_TABLE_LOGIN_HISTORY: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_LOGIN_HISTORY")
        .unwrap_or_else(|_| format!("{}{}", *DB_TABLE_PREFIX, "login_history"))
});
