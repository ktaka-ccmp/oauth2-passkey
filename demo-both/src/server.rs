use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    let config = RustlsConfig::from_pem_file(
        format!("{}/self_signed_certs/cert.pem", env!("CARGO_MANIFEST_DIR")),
        format!("{}/self_signed_certs/key.pem", env!("CARGO_MANIFEST_DIR")),
    )
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
                "oauth2_passkey_axum=trace,oauth2_passkey=trace,{}=trace,info",
                app_name
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
    tracing::info!("Debug mode enabled - showing detailed logs by default");
    tracing::info!("You can increase verbosity by setting the RUST_LOG environment variable.");
    tracing::info!("Log levels from least to most verbose: error < warn < info < debug < trace");
    tracing::info!("Example: RUST_LOG=debug ./demo-xxxxx");

    // Print the current log level
    #[cfg(debug_assertions)]
    tracing::info!("Current log level: DEBUG build with detailed logging");
    #[cfg(not(debug_assertions))]
    tracing::info!("Current log level: RELEASE build with standard logging");
}
