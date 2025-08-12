//! Centralized test setup utilities
//!
//! This module provides standardized test setup patterns to reduce boilerplate
//! and ensure consistent initialization across integration tests.

use crate::common::{MockBrowser, TestServer};

/// Standard test setup with server and browser
pub struct TestSetup {
    pub server: TestServer,
    pub browser: MockBrowser,
}

impl TestSetup {
    /// Create a new test setup with server and browser
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser = MockBrowser::new(&server.base_url, true);
        Ok(Self { server, browser })
    }

    /// Create a new test setup with server, browser, and library initialization
    pub async fn new_with_init() -> Result<Self, Box<dyn std::error::Error>> {
        let setup = Self::new().await?;
        oauth2_passkey::init().await?;
        Ok(setup)
    }

    /// Shutdown the test server
    pub async fn shutdown(self) {
        self.server.shutdown().await;
    }
}

/// Multi-browser test setup for cross-user testing
pub struct MultiBrowserTestSetup {
    pub server: TestServer,
    pub browser1: MockBrowser,
    pub browser2: MockBrowser,
}

impl MultiBrowserTestSetup {
    /// Create a new multi-browser test setup
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser1 = MockBrowser::new(&server.base_url, true);
        let browser2 = MockBrowser::new(&server.base_url, true);
        Ok(Self {
            server,
            browser1,
            browser2,
        })
    }

    /// Shutdown the test server
    pub async fn shutdown(self) {
        self.server.shutdown().await;
    }
}
