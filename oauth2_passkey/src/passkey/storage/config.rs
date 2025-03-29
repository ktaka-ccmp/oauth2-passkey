use std::{env, sync::LazyLock};

use crate::storage::DB_TABLE_PREFIX;

/// Passkey credentials table name
pub(super) static DB_TABLE_PASSKEY_CREDENTIALS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_PASSKEY_CREDENTIALS")
        .unwrap_or_else(|_| format!("{}{}", *DB_TABLE_PREFIX, "passkey_credentials"))
});
