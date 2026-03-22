use crate::test_utils::init_test_environment;
use serial_test::serial;

use super::super::LoginHistoryStore;

/// Test cleanup_old_login_history returns Ok(0) when retention is disabled (default)
#[tokio::test]
#[serial]
async fn test_cleanup_old_login_history_disabled() {
    init_test_environment().await;
    let _ = LoginHistoryStore::init().await;

    // O2P_LOGIN_HISTORY_RETENTION_DAYS defaults to 0 (disabled)
    let result = crate::cleanup_old_login_history().await;
    assert!(result.is_ok(), "Should succeed when disabled");
    assert_eq!(result.unwrap(), 0, "Should return 0 when disabled");
}
