use sqlx::{Pool, Postgres, Row};
use tracing;

/// Validates that a database table schema matches what we expect
pub async fn validate_postgres_table_schema<E>(
    pool: &Pool<Postgres>,
    table_name: &str,
    expected_columns: &[(&str, &str)],
    error_mapper: impl Fn(String) -> E,
) -> Result<(), E> {
    // Check if table exists
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = $1)",
    )
    .bind(table_name)
    .fetch_one(pool)
    .await
    .map_err(|e| error_mapper(e.to_string()))?;

    if !table_exists {
        return Err(error_mapper(format!(
            "Schema validation failed: Table '{}' does not exist",
            table_name
        )));
    }

    // Query actual schema from database
    let rows = sqlx::query(
        "SELECT column_name, data_type FROM information_schema.columns 
         WHERE table_name = $1 ORDER BY column_name",
    )
    .bind(table_name)
    .fetch_all(pool)
    .await
    .map_err(|e| error_mapper(e.to_string()))?;

    let actual_columns: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let name: String = row.get("column_name");
            let type_: String = row.get("data_type");
            (name, type_)
        })
        .collect();

    // Compare schemas
    for (expected_name, expected_type) in expected_columns {
        let found = actual_columns
            .iter()
            .find(|(name, _)| name == expected_name);

        match found {
            Some((_, actual_type)) if actual_type == expected_type => {
                // Column exists with correct type, all good
            }
            Some((_, actual_type)) => {
                // Column exists but with wrong type
                return Err(error_mapper(format!(
                    "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
                    expected_name, actual_type, expected_type
                )));
            }
            None => {
                // Column doesn't exist
                return Err(error_mapper(format!(
                    "Schema validation failed: Missing column '{}'",
                    expected_name
                )));
            }
        }
    }

    // Check for extra columns (just log a warning)
    for (actual_name, _) in &actual_columns {
        if !expected_columns
            .iter()
            .any(|(name, _)| *name == actual_name)
        {
            // Log a warning about extra column
            tracing::warn!(
                "Extra column '{}' found in table '{}'",
                actual_name,
                table_name
            );
        }
    }

    Ok(())
}
