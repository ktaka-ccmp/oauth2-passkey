use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::sync::LazyLock;
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// TLS certificate path (enables HTTPS when set)
pub(crate) static TLS_CERT_PATH: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("TLS_CERT_PATH").ok());

/// TLS private key path
pub(crate) static TLS_KEY_PATH: LazyLock<Option<String>> =
    LazyLock::new(|| std::env::var("TLS_KEY_PATH").ok());

/// Check if TLS is configured
pub(crate) fn is_tls_configured() -> bool {
    TLS_CERT_PATH.is_some() && TLS_KEY_PATH.is_some()
}

pub(crate) fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("HTTP server listening on {}", addr);
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

pub(crate) async fn spawn_https_server(port: u16, app: Router) -> JoinHandle<()> {
    let cert_path = TLS_CERT_PATH
        .as_ref()
        .expect("TLS_CERT_PATH must be set for HTTPS");
    let key_path = TLS_KEY_PATH
        .as_ref()
        .expect("TLS_KEY_PATH must be set for HTTPS");

    let config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .expect("Failed to load TLS certificates");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("HTTPS server listening on {}", addr);
    tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

pub(crate) fn init_tracing(app_name: &str) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        #[cfg(debug_assertions)]
        {
            format!(
                "oauth2_passkey_axum=debug,oauth2_passkey=debug,{app_name}=debug,tower_http=debug"
            )
            .into()
        }

        #[cfg(not(debug_assertions))]
        {
            "info".into()
        }
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(debug_assertions)]
    tracing::debug!("Debug mode enabled - showing detailed logs by default");
    tracing::info!("You can increase verbosity by setting the RUST_LOG environment variable.");
}
