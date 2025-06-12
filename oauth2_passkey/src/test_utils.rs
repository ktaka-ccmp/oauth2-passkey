//! Test utilities module for shared test initialization and helpers
//!
//! This module provides centralized test setup functionality that can be used
//! across all test modules in the crate to ensure consistent environment
//! configuration and database initialization.
//!
//! ## Robust Test Initialization
//!
//! This module provides utilities for setting up a clean test environment with proper
//! database initialization and error handling. Each test gets its own isolated SQLite
//! in-memory database to prevent test interference.

use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};
use std::sync::Once;
use thiserror::Error;
use tracing::{debug, error, info};

#[derive(Debug, Error)]
pub enum TestInitError {
    #[error("Failed to initialize database: {0}")]
    DatabaseInit(String),
    #[error("Environment initialization failed: {0}")]
    EnvInit(String),
}

/// Centralized test initialization for all tests across the entire crate
///
/// This function ensures that:
/// 1. Test environment variables are loaded from .env_test (with fallback to .env)
/// 2. All database stores are properly initialized with tables created
/// 3. Each test gets a clean, isolated database instance
///
/// # Errors
/// Returns `TestInitError` if initialization fails
///
/// # Usage
/// ```rust
/// use crate::test_utils::init_test_environment;
///
/// #[tokio::test]
/// async fn my_test() -> Result<(), Box<dyn std::error::Error>> {
///     init_test_environment().await?;
///     // ... test code that requires database access
///     Ok(())
/// }
/// ```
pub async fn init_test_environment() -> Result<(), TestInitError> {
    // Environment setup (synchronous, runs once)
    static ENV_INIT: Once = Once::new();
    let env_result = std::panic::catch_unwind(|| {
        ENV_INIT.call_once(|| {
            // Try to load .env_test first, fallback to .env if it doesn't exist
            dotenv::from_filename(".env_test")
                .or_else(|_| dotenv::dotenv())
                .map_err(|e| {
                    error!("Failed to load .env file: {}", e);
                    TestInitError::EnvInit(e.to_string())
                })
                .ok();
        });
    });

    if let Err(_) = env_result {
        return Err(TestInitError::EnvInit(
            "Panic during environment initialization".to_string(),
        ));
    }

    // Initialize database with proper error handling
    ensure_database_initialized().await?;

    Ok(())
}

/// Ensures database is properly initialized with all required tables
async fn ensure_database_initialized() -> Result<(), TestInitError> {
    use crate::oauth2::OAuth2Store;
    use crate::passkey::PasskeyStore;
    use crate::userdb::UserStore;

    info!("Initializing database tables...");

    // Initialize each store with proper error handling
    UserStore::init()
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("UserStore init failed: {}", e)))?;

    OAuth2Store::init()
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("OAuth2Store init failed: {}", e)))?;

    PasskeyStore::init()
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("PasskeyStore init failed: {}", e)))?;

    info!("Database initialization completed successfully");
    Ok(())
}

/// Creates a new isolated SQLite in-memory database connection for testing
///
/// This function creates a completely isolated SQLite in-memory database with all
/// necessary tables initialized. Each call to this function returns a new, independent
/// database instance, ensuring test isolation.
///
/// # Returns
/// A `Result` containing the SQLite connection pool or a `TestInitError` if initialization fails
pub async fn create_isolated_db() -> Result<Pool<Sqlite>, TestInitError> {
    use crate::oauth2::OAuth2Store;
    use crate::passkey::PasskeyStore;
    use crate::userdb::UserStore;

    // Create a new in-memory SQLite database with a unique name to ensure isolation
    // Using a random suffix prevents connection sharing between tests
    let db_url = format!(
        "file:testdb_{}?mode=memory&cache=shared&_pragma=foreign_keys(1)",
        uuid::Uuid::new_v4()
    );

    debug!("Creating isolated database: {}", db_url);

    // Create a new connection pool with a single connection for test isolation
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .map_err(|e| {
            TestInitError::DatabaseInit(format!("Failed to create database pool: {}", e))
        })?;

    // Enable foreign key support
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(&pool)
        .await
        .map_err(|e| {
            TestInitError::DatabaseInit(format!("Failed to enable foreign keys: {}", e))
        })?;

    // Initialize all stores using init_with_pool
    debug!("Initializing UserStore tables...");
    UserStore::init_with_pool(&pool)
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("UserStore init failed: {}", e)))?;

    debug!("Initializing OAuth2Store tables...");
    OAuth2Store::init_with_pool(&pool)
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("OAuth2Store init failed: {}", e)))?;

    debug!("Initializing PasskeyStore tables...");
    PasskeyStore::init_with_pool(&pool)
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("PasskeyStore init failed: {}", e)))?;

    debug!("Database initialization completed successfully");
    Ok(pool)
}

/// Test context that manages an isolated database connection
///
/// This struct provides a convenient way to manage the lifecycle of an isolated
/// database connection for tests. When dropped, it will automatically clean up
/// the database connection.
pub struct TestDatabase {
    pool: Pool<Sqlite>,
}

impl TestDatabase {
    /// Create a new test database with all tables initialized
    pub async fn new() -> Result<Self, TestInitError> {
        let pool = create_isolated_db().await?;
        Ok(Self { pool })
    }

    /// Get a reference to the database pool
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Run migrations on the test database
    pub async fn migrate(&self) -> Result<(), TestInitError> {
        // This can be expanded to run any necessary migrations
        Ok(())
    }

    /// Clear all data from all tables in the test database
    pub async fn clear_all_tables(&self) -> Result<(), TestInitError> {
        let mut conn = self.pool.acquire().await.map_err(|e| {
            TestInitError::DatabaseInit(format!("Failed to acquire connection: {}", e))
        })?;

        // Disable foreign key checks temporarily
        sqlx::query("PRAGMA foreign_keys = OFF;")
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                TestInitError::DatabaseInit(format!("Failed to disable foreign keys: {}", e))
            })?;

        // Get all tables
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| TestInitError::DatabaseInit(format!("Failed to get tables: {}", e)))?;

        // Delete all data from each table
        for table in tables {
            let query = format!("DELETE FROM {}", table);
            sqlx::query(&query).execute(&self.pool).await.map_err(|e| {
                TestInitError::DatabaseInit(format!("Failed to clear table {}: {}", table, e))
            })?;
        }

        // Re-enable foreign key checks
        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                TestInitError::DatabaseInit(format!("Failed to re-enable foreign keys: {}", e))
            })?;

        Ok(())
    }
}

/// Helper macro to initialize test environment and handle errors
#[macro_export]
macro_rules! test_init {
    () => {
        $crate::test_utils::init_test_environment()
            .await
            .expect("Failed to initialize test environment");
    };
}
