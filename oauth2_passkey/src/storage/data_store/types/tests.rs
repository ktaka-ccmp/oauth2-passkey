use super::*;

#[test]
fn test_data_store_trait_bounds() {
    // Verify that the trait bounds are correctly enforced for Send + Sync
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<SqliteDataStore>();
    assert_send_sync::<PostgresDataStore>();
    assert_send_sync::<MySqlDataStore>();
    assert_send_sync::<Box<dyn DataStore>>();
}
