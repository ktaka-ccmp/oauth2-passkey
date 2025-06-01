use oauth2_passkey::oauth2::errors::OAuth2Error;
use oauth2_passkey::oauth2::types::OAuth2Mode;
use oauth2_passkey::storage::schema_validation::validate_postgres_table_schema;
use sqlx::{Pool, Postgres};
use std::env;
use std::str::FromStr;

// Helper function to set up a PostgreSQL test database
async fn setup_postgres_test_db() -> Result<Pool<Postgres>, Box<dyn std::error::Error>> {
    // Generate a unique timestamp for this test run to avoid conflicts
    let timestamp = chrono::Utc::now().timestamp_millis();
    let table_prefix = format!("test_o2p_{}_", timestamp);

    // PostgreSQL connection string - should be configurable for CI/CD
    let db_url = env::var("TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/postgres".to_string());

    // Set environment variables for the test
    unsafe {
        env::set_var("GENERIC_DATA_STORE_TYPE", "postgres");
        env::set_var("GENERIC_DATA_STORE_URL", &db_url);
        env::set_var("DB_TABLE_PREFIX", &table_prefix);
    }

    // Connect to the database
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    Ok(pool)
}

// Helper function to clean up after tests
async fn cleanup_postgres_test_db(
    pool: &Pool<Postgres>,
    tables: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    for table in tables {
        sqlx::query(&format!("DROP TABLE IF EXISTS {}", table))
            .execute(pool)
            .await?;
    }
    Ok(())
}
