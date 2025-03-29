use std::{env, sync::LazyLock};

use crate::storage::DB_TABLE_PREFIX;

/// OAuth2 accounts table name
pub(super) static DB_TABLE_OAUTH2_ACCOUNTS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_OAUTH2_ACCOUNTS")
        .unwrap_or_else(|_| format!("{}{}", *DB_TABLE_PREFIX, "oauth2_accounts"))
});
