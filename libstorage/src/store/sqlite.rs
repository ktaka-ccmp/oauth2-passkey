use async_trait::async_trait;
use sqlx::{
    sqlite::{SqlitePool, SqliteRow},
    types::chrono::Utc,
    Row,
};

use crate::{
    store::traits::{RawCacheStore, RawPermanentStore, Store},
    types::{CacheDataKind, PermanentDataKind, QueryField, StorageError},
};

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let pool = SqlitePool::connect(url).await?;
        Ok(Self { pool })
    }

    async fn init_schema(&self) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS cache_store (
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                value BLOB NOT NULL,
                expiry INTEGER,
                PRIMARY KEY (kind, key)
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                data BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                user_handle TEXT NOT NULL,
                data BLOB NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[async_trait]
impl Store for SqliteStore {
    fn requires_schema(&self) -> bool {
        true
    }

    async fn init(&self) -> Result<(), StorageError> {
        self.init_schema().await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

#[async_trait]
impl RawCacheStore for SqliteStore {
    async fn put_raw(
        &mut self,
        kind: CacheDataKind,
        key: &str,
        value: Vec<u8>,
        ttl: Option<u64>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO cache_store (kind, key, value, expiry)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(kind, key) DO UPDATE SET
                value = excluded.value,
                expiry = excluded.expiry
            "#,
        )
        .bind(kind.to_string())
        .bind(key)
        .bind(value)
        .bind(ttl.map(|t| (Utc::now().timestamp() as i64 + t as i64)))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT value FROM cache_store
            WHERE kind = ? AND key = ?
                AND (expiry IS NULL OR expiry > ?)
            "#,
        )
        .bind(kind.to_string())
        .bind(key)
        .bind(Utc::now().timestamp())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r: SqliteRow| r.get("value")))
    }

    async fn query_raw(
        &self,
        kind: CacheDataKind,
        key: &str,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT value FROM cache_store
            WHERE kind = ? AND key LIKE ?
                AND (expiry IS NULL OR expiry > ?)
            "#,
        )
        .bind(kind.to_string())
        .bind(format!("{}%", key))
        .bind(Utc::now().timestamp())
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r: SqliteRow| r.get("value"))
            .collect())
    }

    async fn delete(&mut self, kind: CacheDataKind, key: &str) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            DELETE FROM cache_store
            WHERE kind = ? AND key = ?
            "#,
        )
        .bind(kind.to_string())
        .bind(key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[async_trait]
impl RawPermanentStore for SqliteStore {
    async fn store_raw(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => {
                sqlx::query(
                    r#"
                    INSERT OR REPLACE INTO users (id, email, data)
                    VALUES (?, ?, ?)
                    "#,
                )
                .bind(key)
                .bind(key) // Using key as email for users
                .bind(value)
                .execute(&self.pool)
                .await?;
            }
            PermanentDataKind::Credential => {
                sqlx::query(
                    r#"
                    INSERT OR REPLACE INTO credentials (id, user_handle, data)
                    VALUES (?, ?, ?)
                    "#,
                )
                .bind(key)
                .bind(key) // Using key as user_handle for credentials
                .bind(value)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    async fn get_raw(
        &self,
        kind: PermanentDataKind,
        key: &str,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let row = match kind {
            PermanentDataKind::User => {
                sqlx::query("SELECT data FROM users WHERE id = ?")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
            PermanentDataKind::Credential => {
                sqlx::query("SELECT data FROM credentials WHERE id = ?")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
        };

        Ok(row.map(|r: SqliteRow| r.get("data")))
    }

    async fn query_raw(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let rows = match (kind, field) {
            (PermanentDataKind::User, QueryField::Email(email)) => {
                sqlx::query("SELECT data FROM users WHERE email = ?")
                    .bind(email)
                    .fetch_all(&self.pool)
                    .await?
            }
            (PermanentDataKind::Credential, QueryField::UserHandle(handle)) => {
                sqlx::query("SELECT data FROM credentials WHERE user_handle = ?")
                    .bind(handle)
                    .fetch_all(&self.pool)
                    .await?
            }
            _ => return Ok(Vec::new()),
        };

        Ok(rows.into_iter().map(|r: SqliteRow| r.get("data")).collect())
    }

    async fn delete(&mut self, kind: PermanentDataKind, key: &str) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => {
                sqlx::query("DELETE FROM users WHERE id = ?")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
            PermanentDataKind::Credential => {
                sqlx::query("DELETE FROM credentials WHERE id = ?")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }

        Ok(())
    }
}
