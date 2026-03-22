//! Configuration for login history table

use std::{env, sync::LazyLock};

use crate::storage::DB_TABLE_PREFIX;

/// Login history table name
pub(super) static DB_TABLE_LOGIN_HISTORY: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_LOGIN_HISTORY")
        .unwrap_or_else(|_| format!("{}{}", *DB_TABLE_PREFIX, "login_history"))
});

/// Number of days to retain login history entries. 0 = disabled (no automatic cleanup).
pub(in crate::audit) static O2P_LOGIN_HISTORY_RETENTION_DAYS: LazyLock<u32> = LazyLock::new(|| {
    match env::var("O2P_LOGIN_HISTORY_RETENTION_DAYS") {
        Err(_) => 0,
        Ok(val) => match val.parse::<u32>() {
            Ok(0) => 0,
            Ok(days) => days,
            Err(_) => panic!(
                "O2P_LOGIN_HISTORY_RETENTION_DAYS='{val}' is invalid. Must be a non-negative integer (0 = disabled)"
            ),
        },
    }
});
