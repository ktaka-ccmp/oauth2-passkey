use async_trait::async_trait;
use sqlx::{postgres::PgPool, Row};

use crate::{
    store::traits::{RawPermanentStore, Store},
    types::{PermanentDataKind, QueryField, StorageError},
};

pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let pool = PgPool::connect(url).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl Store for PostgresStore {
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
impl RawPermanentStore for PostgresStore {
    async fn store_raw(
        &mut self,
        kind: PermanentDataKind,
        key: &str,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => {
                sqlx::query("INSERT INTO users (id, email, data) VALUES ($1, $1, $2) ON CONFLICT (id) DO UPDATE SET data = $2")
                    .bind(key)
                    .bind(&value)
                    .execute(&self.pool)
                    .await?;
            }
            PermanentDataKind::Credential => {
                sqlx::query(
                    "INSERT INTO credentials (id, user_handle, data) VALUES ($1, $1, $2) ON CONFLICT (id) DO UPDATE SET data = $2",
                )
                .bind(key)
                .bind(&value)
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
        let result = match kind {
            PermanentDataKind::User => {
                sqlx::query("SELECT data FROM users WHERE id = $1")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
            PermanentDataKind::Credential => {
                sqlx::query("SELECT data FROM credentials WHERE id = $1")
                    .bind(key)
                    .fetch_optional(&self.pool)
                    .await?
            }
        };

        Ok(result.map(|row| row.get("data")))
    }

    async fn query_raw(
        &self,
        kind: PermanentDataKind,
        field: QueryField,
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let rows = match (kind, field) {
            (PermanentDataKind::User, QueryField::Email(email)) => {
                sqlx::query("SELECT data FROM users WHERE email = $1")
                    .bind(email)
                    .fetch_all(&self.pool)
                    .await?
            }
            (PermanentDataKind::Credential, QueryField::UserHandle(handle)) => {
                sqlx::query("SELECT data FROM credentials WHERE user_handle = $1")
                    .bind(handle)
                    .fetch_all(&self.pool)
                    .await?
            }
            _ => return Ok(Vec::new()),
        };

        Ok(rows.into_iter().map(|row| row.get("data")).collect())
    }

    async fn delete(&mut self, kind: PermanentDataKind, key: &str) -> Result<(), StorageError> {
        match kind {
            PermanentDataKind::User => {
                sqlx::query("DELETE FROM users WHERE id = $1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
            PermanentDataKind::Credential => {
                sqlx::query("DELETE FROM credentials WHERE id = $1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }
}

impl PostgresStore {
    async fn init_schema(&self) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                data BYTEA NOT NULL
            );
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                user_handle TEXT NOT NULL,
                data BYTEA NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
