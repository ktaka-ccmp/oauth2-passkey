use super::*;

#[test]
fn test_error_is_sync_and_send() {
    fn assert_sync_send<T: Sync + Send>() {}
    assert_sync_send::<CoordinationError>();
}

#[test]
fn test_error_log() {
    // Test that the log method returns self and works correctly
    let err = CoordinationError::Coordination("test error".to_string());
    let logged_err = err.log();

    if let CoordinationError::Coordination(msg) = logged_err {
        assert_eq!(msg, "test error");
    } else {
        panic!("Wrong error type after logging");
    }
}
