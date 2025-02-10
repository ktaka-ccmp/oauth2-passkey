use std::time::Duration;

pub(crate) fn get_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(1)
        .build()
        .expect("Failed to create reqwest client")
}
