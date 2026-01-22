use super::*;

#[test]
fn test_extract_sqlite_file_path_from_url() {
    // Test sqlite: with absolute path
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:/tmp/test.db"),
        Some("/tmp/test.db".to_string())
    );

    // Test sqlite: with relative path
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:./test.db"),
        Some("./test.db".to_string())
    );

    // Test sqlite:file: format
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:file:/tmp/test.db"),
        Some("/tmp/test.db".to_string())
    );

    // Test sqlite:file: with query parameters
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:file:/tmp/test.db?mode=rwc&cache=shared"),
        Some("/tmp/test.db".to_string())
    );

    // Test in-memory database with query parameter (should still extract path)
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:file:test?mode=memory&cache=shared"),
        Some("test".to_string())
    );

    // Test :memory: database (should return None)
    assert_eq!(extract_sqlite_file_path_from_url("sqlite::memory:"), None);

    // Test file:memory: database (should return None)
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:file:test_integrated?mode=memory&cache=shared"),
        Some("test_integrated".to_string())
    );

    // Test actual :memory: in path (should return None)
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:file::memory:?cache=shared"),
        None
    );

    // Test non-SQLite URL (should return None)
    assert_eq!(
        extract_sqlite_file_path_from_url("postgresql://localhost/test"),
        None
    );

    // Test empty string (should return None)
    assert_eq!(extract_sqlite_file_path_from_url(""), None);

    // Test sqlite with double slash format
    assert_eq!(
        extract_sqlite_file_path_from_url("sqlite:///tmp/test.db"),
        Some("/tmp/test.db".to_string())
    );
}
