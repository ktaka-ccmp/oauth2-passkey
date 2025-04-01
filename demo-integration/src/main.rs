mod handlers;
mod server;

use axum::{Router, middleware::from_fn, routing::get};
use dotenv::dotenv;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use oauth2_passkey_axum::{
    O2P_ROUTE_PREFIX, is_authenticated_or_redirect, is_authenticated_with_user,
    oauth2_passkey_router, passkey_well_known_router,
};

use handlers::{index, p1, p2, p3, p4, protected};
use server::{Ports, spawn_http_server, spawn_https_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install default CryptoProvider for rustls to prevent:
    // "no process-level CryptoProvider available -- call CryptoProvider::install_default() before this point"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default CryptoProvider");

    dotenv().ok();

    // Set up tracing with environment variable support and different defaults based on build configuration
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // If no environment variable is set, use different defaults based on build configuration
        #[cfg(debug_assertions)]
        {
            // Debug build default - show all log levels
            "oauth2_passkey_axum=trace,oauth2_passkey=trace,demo_integration=trace".into()
        }

        #[cfg(not(debug_assertions))]
        {
            // Release build default - only show info and above
            "info".into()
        }
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(debug_assertions)]
    tracing::debug!("Debug mode enabled - showing detailed logs by default");

    tracing::info!("Starting demo-integration application");
    tracing::info!("You can increase verbosity by setting the RUST_LOG environment variable.");
    tracing::info!("Log levels from least to most verbose: error < warn < info < debug < trace");
    tracing::info!("Example: RUST_LOG=debug ./demo-integration");
    tracing::info!("O2P_ROUTE_PREFIX: {}", O2P_ROUTE_PREFIX.as_str());

    // Print the current log level
    #[cfg(debug_assertions)]
    tracing::info!("Current log level: DEBUG build with detailed logging");
    #[cfg(not(debug_assertions))]
    tracing::info!("Current log level: RELEASE build with standard logging");

    // Add a handler for errors that suggests increasing log level
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("ERROR: The application encountered a problem and needs to close.");
        eprintln!(
            "For more detailed error information, run with: RUST_LOG=debug ./your-application"
        );
        eprintln!("Panic details: {}", panic_info);
    }));

    // Initialize the authentication library
    tracing::info!("Initializing authentication library");
    oauth2_passkey_axum::init().await?;

    // Define custom redirect URL for authentication
    // If None, will return 401 Unauthorized instead of redirecting
    // let redirect = Some("/");
    let redirect = None;

    let app = Router::new()
        .route("/", get(index))
        .route("/protected", get(protected))
        .route(
            "/p1",
            get(p1).route_layer(from_fn(move |req, next| {
                is_authenticated_or_redirect(redirect, req, next)
            })),
        )
        .route(
            "/p2",
            get(p2).route_layer(from_fn(is_authenticated_with_user)),
        )
        .route("/p3", get(p3))
        .route("/p4", get(p4))
        .nest(O2P_ROUTE_PREFIX.as_str(), oauth2_passkey_router())
        .nest("/.well-known", passkey_well_known_router()); // Mount the WebAuthn well-known endpoint at root level

    let ports = Ports {
        http: 3001,
        https: 3443,
    };

    let http_server = spawn_http_server(ports.http, app.clone());
    let https_server = spawn_https_server(ports.https, app).await;

    // Wait for both servers to complete (which they never will in this case)
    tokio::try_join!(http_server, https_server).unwrap();
    Ok(())
}
