//! Shared plumbing for the PeSIT Wizard server and client binaries.

pub mod http;
pub mod store;
pub mod time;

/// Initialise tracing from `RUST_LOG` (default `info`).
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,pesit=debug"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}
