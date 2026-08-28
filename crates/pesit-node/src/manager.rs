//! Lifecycle of the PeSIT listeners.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pesit_app::store::JsonStore;
use pesit_app::time::now_iso;
use pesit_io::responder::{self, ResponderConfig, ServerHandler};
use pesit_io::tls::{self, TlsAcceptor, TlsServerSettings};
use pesit_io::transport::Framing;
use rustc_hash::FxHashMap;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::handler::{CancelRegistry, PwHandler};
use crate::model::{tables, PesitServerConfig, ServerStatus, ServerStatusResponse};

/// Manager error.
#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    /// Unknown listener.
    #[error("server '{0}' not found")]
    NotFound(String),
    /// Already running.
    #[error("server '{0}' is already running")]
    AlreadyRunning(String),
    /// Not running.
    #[error("server '{0}' is not running")]
    NotRunning(String),
    /// Cannot bind.
    #[error("cannot listen on {0}: {1}")]
    Bind(String, std::io::Error),
    /// TLS misconfiguration.
    #[error("TLS: {0}")]
    Tls(String),
    /// Storage error.
    #[error("{0}")]
    Store(#[from] pesit_app::store::StoreError),
}

struct Running {
    shutdown: watch::Sender<bool>,
    active: Arc<AtomicUsize>,
    port: u16,
}

/// Process-wide settings needed by listeners.
pub struct ListenerSettings {
    /// Checkpoint directory.
    pub checkpoint_dir: PathBuf,
    /// Node identifier.
    pub node_id: String,
    /// TLS settings when TLS is enabled.
    pub tls: Option<TlsServerSettings>,
}

/// Starts and stops listeners.
pub struct ServerManager {
    store: Arc<JsonStore>,
    settings: ListenerSettings,
    running: Mutex<FxHashMap<String, Running>>,
    /// Cancellation registry shared with the REST API.
    pub cancels: Arc<CancelRegistry>,
    conn_counter: AtomicU32,
}

impl ServerManager {
    /// Create the manager.
    #[must_use]
    pub fn new(store: Arc<JsonStore>, settings: ListenerSettings) -> Self {
        Self {
            store,
            settings,
            running: Mutex::new(FxHashMap::default()),
            cancels: Arc::new(CancelRegistry::default()),
            conn_counter: AtomicU32::new(0),
        }
    }

    /// Whether a listener is running.
    #[must_use]
    pub fn is_running(&self, server_id: &str) -> bool {
        self.running
            .lock()
            .map(|r| r.contains_key(server_id))
            .unwrap_or(false)
    }

    /// Status of a listener.
    #[must_use]
    pub fn status(&self, cfg: &PesitServerConfig) -> ServerStatusResponse {
        let running = self.running.lock().ok();
        let r = running.as_ref().and_then(|m| m.get(&cfg.server_id));
        ServerStatusResponse {
            server_id: cfg.server_id.clone(),
            status: if r.is_some() {
                ServerStatus::Running
            } else if cfg.status == ServerStatus::Error {
                ServerStatus::Error
            } else {
                ServerStatus::Stopped
            },
            running: r.is_some(),
            active_connections: r.map_or(0, |r| r.active.load(Ordering::Relaxed)),
            port: r.map_or(cfg.port, |r| r.port),
        }
    }

    fn set_status(&self, server_id: &str, status: ServerStatus) {
        let _ = self
            .store
            .update::<PesitServerConfig>(tables::SERVERS, server_id, |c| {
                c.status = status;
                c.updated_at = Some(now_iso());
                match status {
                    ServerStatus::Running => c.last_started_at = Some(now_iso()),
                    ServerStatus::Stopped => c.last_stopped_at = Some(now_iso()),
                    _ => {}
                }
            });
    }

    /// Start a listener.
    pub async fn start(&self, server_id: &str) -> Result<(), ManagerError> {
        if self.is_running(server_id) {
            return Err(ManagerError::AlreadyRunning(server_id.to_owned()));
        }
        let cfg: PesitServerConfig = self
            .store
            .get(tables::SERVERS, server_id)?
            .ok_or_else(|| ManagerError::NotFound(server_id.to_owned()))?;
        let acceptor = if cfg.ssl_enabled {
            let Some(settings) = &self.settings.tls else {
                self.set_status(server_id, ServerStatus::Error);
                return Err(ManagerError::Tls(
                    "listener requires TLS but PESIT_SSL_ENABLED / certificate paths are not set"
                        .into(),
                ));
            };
            Some(tls::acceptor(settings).map_err(|e| ManagerError::Tls(e.to_string()))?)
        } else {
            None
        };
        let addr = format!("{}:{}", cfg.bind_address, cfg.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                self.set_status(server_id, ServerStatus::Error);
                return Err(ManagerError::Bind(addr, e));
            }
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let active = Arc::new(AtomicUsize::new(0));
        let handler: Arc<dyn ServerHandler> = Arc::new(PwHandler::new(
            Arc::clone(&self.store),
            cfg.clone(),
            self.settings.checkpoint_dir.clone(),
            self.settings.node_id.clone(),
            Arc::clone(&self.cancels),
        ));
        let ctx = Arc::new(AcceptContext {
            cfg: cfg.clone(),
            handler,
            acceptor,
            active: Arc::clone(&active),
            counter: AtomicU32::new(self.conn_counter.fetch_add(1000, Ordering::Relaxed)),
        });
        tokio::spawn(accept_loop(listener, ctx, shutdown_rx));
        if let Ok(mut r) = self.running.lock() {
            r.insert(
                server_id.to_owned(),
                Running {
                    shutdown: shutdown_tx,
                    active,
                    port: cfg.port,
                },
            );
        }
        self.set_status(server_id, ServerStatus::Running);
        tracing::info!(
            "PeSIT listener '{}' started on {addr}{}",
            server_id,
            if cfg.ssl_enabled { " (TLS)" } else { "" }
        );
        Ok(())
    }

    /// Stop a listener (sessions in progress are not interrupted).
    pub fn stop(&self, server_id: &str) -> Result<(), ManagerError> {
        let removed = self
            .running
            .lock()
            .ok()
            .and_then(|mut r| r.remove(server_id));
        let Some(r) = removed else {
            if self.store.exists(tables::SERVERS, server_id)? {
                return Err(ManagerError::NotRunning(server_id.to_owned()));
            }
            return Err(ManagerError::NotFound(server_id.to_owned()));
        };
        let _ = r.shutdown.send(true);
        self.set_status(server_id, ServerStatus::Stopped);
        tracing::info!("PeSIT listener '{server_id}' stopped");
        Ok(())
    }

    /// Start every listener flagged `autoStart`.
    pub async fn start_auto(&self) {
        let servers: Vec<PesitServerConfig> = self.store.list(tables::SERVERS).unwrap_or_default();
        for s in servers {
            if s.auto_start {
                if let Err(e) = self.start(&s.server_id).await {
                    tracing::error!("cannot start listener '{}': {e}", s.server_id);
                }
            } else {
                self.set_status(&s.server_id, ServerStatus::Stopped);
            }
        }
    }

    /// Stop all listeners.
    pub fn stop_all(&self) {
        let ids: Vec<String> = self
            .running
            .lock()
            .map(|r| r.keys().cloned().collect())
            .unwrap_or_default();
        for id in ids {
            let _ = self.stop(&id);
        }
    }
}

struct AcceptContext {
    cfg: PesitServerConfig,
    handler: Arc<dyn ServerHandler>,
    acceptor: Option<TlsAcceptor>,
    active: Arc<AtomicUsize>,
    counter: AtomicU32,
}

async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<AcceptContext>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        if ctx.active.load(Ordering::Relaxed) >= ctx.cfg.max_connections as usize {
                            tracing::warn!("connection from {addr} refused: {} sessions already active", ctx.cfg.max_connections);
                            continue;
                        }
                        let ctx = Arc::clone(&ctx);
                        tokio::spawn(async move {
                            ctx.active.fetch_add(1, Ordering::Relaxed);
                            handle_connection(stream, addr, &ctx).await;
                            ctx.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        tracing::error!("accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn handle_connection(stream: tokio::net::TcpStream, addr: SocketAddr, ctx: &AcceptContext) {
    let _ = stream.set_nodelay(true);
    let n = ctx.counter.fetch_add(1, Ordering::Relaxed);
    let session_id = format!("{}-{n:06}", ctx.cfg.server_id);
    tracing::info!("[{session_id}] connection from {addr}");
    let (stream, framing): (pesit_io::BoxedStream, Framing) = match &ctx.acceptor {
        Some(acceptor) => match acceptor.accept(stream).await {
            Ok(tls) => (
                Box::pin(tls),
                if ctx.cfg.tcpip_header {
                    Framing::LengthPrefixed
                } else {
                    Framing::Raw
                },
            ),
            Err(e) => {
                tracing::warn!("[{session_id}] TLS handshake with {addr} failed: {e}");
                return;
            }
        },
        None => (Box::pin(stream), Framing::LengthPrefixed),
    };
    let rc = ResponderConfig {
        session_id: session_id.clone(),
        conn_id: (n % 254 + 1) as u8,
        timeout: Duration::from_millis(ctx.cfg.read_timeout.max(1000)),
        idle_timeout: Duration::from_millis(
            ctx.cfg
                .connection_timeout
                .max(ctx.cfg.read_timeout)
                .max(1000),
        ),
        remote_addr: addr.to_string(),
    };
    if let Err(e) = responder::serve(stream, framing, rc, Arc::clone(&ctx.handler)).await {
        tracing::warn!("[{session_id}] session ended with error: {e}");
    }
}
