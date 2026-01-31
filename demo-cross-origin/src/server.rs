use axum::Router;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub(crate) fn spawn_http_server(port: u16, app: Router) -> JoinHandle<()> {
    tokio::spawn(async move {
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        tracing::info!("HTTP server listening on {}", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
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
