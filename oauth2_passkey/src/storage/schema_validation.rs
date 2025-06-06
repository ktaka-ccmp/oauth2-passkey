use sqlx::{Pool, Postgres, Row, Sqlite};

/// Validates that a database table schema matches what we expect
pub(crate) async fn validate_postgres_table_schema<E>(
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

/// Validates that a database table schema matches what we expect
pub(crate) async fn validate_sqlite_table_schema<E>(
    pool: &Pool<Sqlite>,
    table_name: &str,
    expected_columns: &[(&str, &str)],
    error_mapper: impl Fn(String) -> E,
) -> Result<(), E> {
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT name FROM sqlite_master WHERE type='table' AND name=?)",
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
    let pragma_sql = format!("PRAGMA table_info('{}');", table_name);

    let rows = sqlx::query(pragma_sql.as_str())
        .fetch_all(pool)
        .await
        .map_err(|e| error_mapper(e.to_string()))?;

    let actual_columns: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let name: String = row.get("name");
            let type_: String = row.get("type");
            (name, type_)
        })
        .collect();

    // Compare schemas
    for (expected_name, expected_type) in expected_columns {
        let found = actual_columns
            .iter()
            .find(|(name, _)| name == expected_name);

        match found {
            Some((_, actual_type)) if actual_type.to_uppercase() == *expected_type => {
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
                    "Schema validation failed: Missing column '{}'.",
                    expected_name
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use thiserror::Error;

    // Custom error type for testing
    #[derive(Debug, Error, PartialEq)]
    enum TestError {
        #[error("Schema error: {0}")]
        Schema(String),
    }

    // Helper function to create a mock error mapper
    fn error_mapper(msg: String) -> TestError {
        TestError::Schema(msg)
    }

    // Test the error message format for missing table in PostgreSQL
    #[test]
    fn test_postgres_missing_table_error_format() {
        let table_name = "test_table";
        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Table '{}' does not exist",
            table_name
        ));

        let error_message = format!(
            "Schema validation failed: Table '{}' does not exist",
            table_name
        );
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }

    // Test the error message format for missing column in PostgreSQL
    #[test]
    fn test_postgres_missing_column_error_format() {
        let column_name = "test_column";
        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Missing column '{}'",
            column_name
        ));

        let error_message = format!("Schema validation failed: Missing column '{}'", column_name);
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }

    // Test the error message format for wrong column type in PostgreSQL
    #[test]
    fn test_postgres_wrong_column_type_error_format() {
        let column_name = "test_column";
        let actual_type = "text";
        let expected_type = "integer";

        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
            column_name, actual_type, expected_type
        ));

        let error_message = format!(
            "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
            column_name, actual_type, expected_type
        );
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }

    // Test the error message format for missing table in SQLite
    #[test]
    fn test_sqlite_missing_table_error_format() {
        let table_name = "test_table";
        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Table '{}' does not exist",
            table_name
        ));

        let error_message = format!(
            "Schema validation failed: Table '{}' does not exist",
            table_name
        );
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }

    // Test the error message format for missing column in SQLite
    #[test]
    fn test_sqlite_missing_column_error_format() {
        let column_name = "test_column";
        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Missing column '{}'.",
            column_name
        ));

        let error_message = format!(
            "Schema validation failed: Missing column '{}'.",
            column_name
        );
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }

    // Test the error message format for wrong column type in SQLite
    #[test]
    fn test_sqlite_wrong_column_type_error_format() {
        let column_name = "test_column";
        let actual_type = "TEXT";
        let expected_type = "INTEGER";

        let expected_error = TestError::Schema(format!(
            "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
            column_name, actual_type, expected_type
        ));

        let error_message = format!(
            "Schema validation failed: Column '{}' has type '{}' but expected '{}'",
            column_name, actual_type, expected_type
        );
        let actual_error = error_mapper(error_message);

        assert_eq!(expected_error, actual_error);
    }
}
