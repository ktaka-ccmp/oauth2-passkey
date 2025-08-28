use super::*;

#[test]
fn test_format_date_tz_jst() {
    // Create a fixed UTC datetime for testing
    let utc_date = DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    // Format with JST timezone
    let formatted = format_date_tz(&utc_date, "JST");

    // JST is UTC+9, so 00:00 UTC becomes 09:00 JST
    assert_eq!(formatted, "2023-01-01 09:00 JST");
}

#[test]
fn test_format_date_tz_pst() {
    // Create a fixed UTC datetime for testing
    let utc_date = DateTime::parse_from_rfc3339("2023-01-01T08:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    // Format with PST timezone (UTC-8)
    let formatted = format_date_tz(&utc_date, "PST");

    // PST is UTC-8, so 08:00 UTC becomes 00:00 PST
    assert_eq!(formatted, "2023-01-01 00:00 PST");
}

#[test]
fn test_format_date_tz_utc() {
    // Create a fixed UTC datetime for testing
    let utc_date = DateTime::parse_from_rfc3339("2023-01-01T12:30:45Z")
        .unwrap()
        .with_timezone(&Utc);

    // Format with UTC timezone
    let formatted = format_date_tz(&utc_date, "UTC");

    // UTC time should remain the same
    assert_eq!(formatted, "2023-01-01 12:30 UTC");
}

#[test]
fn test_format_date_tz_unknown_timezone() {
    // Create a fixed UTC datetime for testing
    let utc_date = DateTime::parse_from_rfc3339("2023-01-01T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    // Format with an unknown timezone (should default to UTC)
    let formatted = format_date_tz(&utc_date, "UNKNOWN");

    // Should default to UTC but display the requested timezone name
    assert_eq!(formatted, "2023-01-01 12:00 UNKNOWN");
}
