//! PeSIT Wizard node: a single process that listens for incoming PeSIT E transfers and initiates
//! outgoing ones, sharing one configuration store and one web UI.
//!
//! Two REST surfaces are exposed for tooling compatibility, both backed by the same store:
//! the admin API on `--api-port` (partners, virtual files, listeners, inbound records, web UI)
//! and the transfer API on `--transfer-port` (remote servers, send/receive/message, outbound
//! history). The web UI reaches the transfer API through the admin API under `/client`.

#![allow(clippy::multiple_crate_versions)]

mod api;
mod audit;
mod backup;
mod cluster;
mod config;
mod handler;
mod manager;
mod model;
mod pki;
mod schedule;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::http::HeaderValue;
use clap::{Args, Parser, Subcommand};
use pesit_app::audit::AuditLog;
use pesit_app::store::JsonStore;
use pesit_app::time::now_iso;
use pesit_client::engine::Engine;
use pesit_client::model as cmodel;

use crate::config::{Bootstrap, NodeOptions};
use crate::manager::{ListenerSettings, ServerManager};
use crate::model::tables;

/// `pesitwizard` — a unified PeSIT E node (listens and initiates).
#[derive(Debug, Parser)]
#[command(name = "pesitwizard", version, about = "PeSIT Wizard node (PeSIT E)")]
struct Cli {
    #[command(flatten)]
    opts: NodeOptions,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the node: listeners + transfer engine + REST APIs + web UI (default).
    Serve,
    /// Send a file to a server (one-shot).
    Send {
        #[command(flatten)]
        target: Target,
        /// Local file to send.
        file: PathBuf,
        /// Virtual file name on the server (PI 12).
        #[arg(long)]
        remote: String,
        /// Text mode (line records).
        #[arg(long)]
        text: bool,
        /// Enable compression.
        #[arg(long)]
        compress: bool,
    },
    /// Receive a file from a server (one-shot).
    Receive {
        #[command(flatten)]
        target: Target,
        /// Virtual file name on the server (PI 12).
        remote: String,
        /// Local destination.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Text mode (line records).
        #[arg(long)]
        text: bool,
    },
    /// Send a message to a server (one-shot).
    Message {
        #[command(flatten)]
        target: Target,
        /// Message text.
        message: String,
        /// Wait for a reply (PI 91).
        #[arg(long)]
        reply: bool,
    },
}

/// Where to connect for one-shot commands.
#[derive(Debug, Args)]
struct Target {
    /// Host.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    /// Port.
    #[arg(long, default_value_t = 5001)]
    port: u16,
    /// Server identifier (PI 4).
    #[arg(long, default_value = "PWSERVER")]
    server_id: String,
    /// Our identifier (PI 3); defaults to `--client-id`.
    #[arg(long)]
    partner: Option<String>,
    /// Password (PI 5).
    #[arg(long)]
    password: Option<String>,
    /// Use TLS.
    #[arg(long)]
    tls: bool,
    /// Use the CRC option.
    #[arg(long)]
    crc: bool,
    /// Disable synchronisation points.
    #[arg(long)]
    no_sync: bool,
    /// Synchronisation interval in KB.
    #[arg(long)]
    sync_kb: Option<u16>,
    /// Pre-connection identifier (partner types T/O).
    #[arg(long)]
    preconnect_id: Option<String>,
    /// Pre-connection password.
    #[arg(long)]
    preconnect_password: Option<String>,
    /// No transport header on TLS connections (TCPIP_HEADER=N).
    #[arg(long)]
    no_tcpip_header: bool,
}

impl Target {
    fn server(&self) -> cmodel::PesitServer {
        cmodel::PesitServer {
            id: "cli".into(),
            name: "cli".into(),
            host: self.host.clone(),
            port: self.port,
            server_id: self.server_id.clone(),
            tls_enabled: self.tls,
            tcpip_header: !self.no_tcpip_header,
            crc_enabled: self.crc,
            preconnect_id: self.preconnect_id.clone(),
            preconnect_password: self.preconnect_password.clone(),
            hostname_verification: false,
            ..cmodel::PesitServer::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pesit_app::init_tracing();
    let cli = Cli::parse();
    let opts = &cli.opts;

    let store = Arc::new(
        JsonStore::open(&opts.db).with_context(|| format!("opening {}", opts.db.display()))?,
    );
    for t in tables::ALL {
        store.ensure_table(t)?;
    }
    for t in cmodel::tables::ALL {
        store.ensure_table(t)?;
    }
    if let Some(path) = &opts.config {
        let boot = Bootstrap::load(path).with_context(|| format!("loading {}", path.display()))?;
        bootstrap(&store, boot)?;
    }

    let audit =
        Arc::new(AuditLog::new(Arc::clone(&store)).map_err(|e| anyhow::anyhow!(e.to_string()))?);
    let engine = Arc::new(Engine::new(
        Arc::clone(&store),
        opts.engine_settings(),
        Arc::clone(&audit),
    ));

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(opts, store, engine, audit).await,
        Command::Send {
            target,
            file,
            remote,
            text,
            compress,
        } => {
            let server = register_cli_server(&store, target.server())?;
            let req = cmodel::TransferRequest {
                server: Some(server.name.clone()),
                partner_id: target.partner.clone(),
                password: target.password.clone(),
                filename: Some(file.to_string_lossy().into_owned()),
                remote_filename: Some(remote),
                sync_points_enabled: Some(!target.no_sync),
                sync_point_interval: target.sync_kb.map(u64::from),
                compression_enabled: Some(compress),
                text: Some(text),
                crc_enabled: Some(target.crc),
                ..cmodel::TransferRequest::default()
            };
            let h = engine
                .submit_send(req)
                .map_err(|e| anyhow::anyhow!(e.message))?;
            wait_and_report(&engine, &h.id).await
        }
        Command::Receive {
            target,
            remote,
            file,
            text,
        } => {
            let server = register_cli_server(&store, target.server())?;
            let req = cmodel::TransferRequest {
                server: Some(server.name.clone()),
                partner_id: target.partner.clone(),
                password: target.password.clone(),
                filename: file.map(|f| f.to_string_lossy().into_owned()),
                remote_filename: Some(remote),
                sync_points_enabled: Some(!target.no_sync),
                sync_point_interval: target.sync_kb.map(u64::from),
                text: Some(text),
                crc_enabled: Some(target.crc),
                ..cmodel::TransferRequest::default()
            };
            let h = engine
                .submit_receive(req)
                .map_err(|e| anyhow::anyhow!(e.message))?;
            wait_and_report(&engine, &h.id).await
        }
        Command::Message {
            target,
            message,
            reply,
        } => {
            let server = register_cli_server(&store, target.server())?;
            let req = cmodel::MessageRequest {
                server: Some(server.name),
                partner_id: target.partner.clone(),
                password: target.password.clone(),
                message,
                expects_reply: reply,
                ..cmodel::MessageRequest::default()
            };
            let r = engine
                .send_message(req)
                .await
                .map_err(|e| anyhow::anyhow!(e.message))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            if r.status != cmodel::TransferStatus::Completed {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

async fn serve(
    opts: &NodeOptions,
    store: Arc<JsonStore>,
    engine: Arc<Engine>,
    audit: Arc<AuditLog>,
) -> anyhow::Result<()> {
    let cluster = if let Some(url) = opts.cluster_nats.clone().filter(|u| !u.is_empty()) {
        let cfg = pesit_cluster::ClusterConfig {
            url,
            name: opts.cluster_name.clone(),
            node_id: opts.node_id.clone(),
            node_addr: opts.advertise_addr.clone().unwrap_or_else(|| {
                let host = std::env::var("HOSTNAME")
                    .ok()
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| opts.api_bind.clone());
                format!("{host}:{}", opts.api_port)
            }),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            heartbeat: std::time::Duration::from_secs(5),
        };
        match pesit_cluster::Cluster::join(cfg, cluster::handler(Arc::clone(&store))).await {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::error!("cluster disabled: {e}");
                None
            }
        }
    } else {
        None
    };
    let tls = opts.listener_tls()?;
    let pki = match pki::PkiState::open(opts.pki_dir.clone(), Arc::clone(&store)) {
        Ok(p) => Some(Arc::new(p)),
        Err(e) => {
            tracing::error!("certificate management disabled: {e}");
            None
        }
    };
    let manager = Arc::new(ServerManager::new(
        Arc::clone(&store),
        ListenerSettings {
            checkpoint_dir: opts.checkpoint_dir.clone(),
            node_id: opts.node_id.clone(),
            tls,
            pki: pki.clone(),
        },
    ));
    manager.start_auto().await;
    schedule::spawn(
        Arc::clone(&store),
        Arc::clone(&engine),
        cluster.clone(),
        Arc::clone(&audit),
    );

    let api_key = if opts.security_enabled {
        opts.api_key
            .as_deref()
            .filter(|k| !k.is_empty())
            .map(HeaderValue::from_str)
            .transpose()?
    } else {
        None
    };
    if api_key.is_none() {
        tracing::warn!("admin API authentication is disabled (set PESIT_API_KEY to enable it)");
    }
    let server_app = Arc::new(api::App {
        store: Arc::clone(&store),
        manager: Arc::clone(&manager),
        api_key,
        pki,
        audit: Arc::clone(&audit),
        cluster: cluster.clone(),
        engine: Arc::clone(&engine),
    });
    let client_app = Arc::new(pesit_client::api::App {
        store: Arc::clone(&store),
        engine: Arc::clone(&engine),
        tls_dir: opts.client_tls_dir.clone(),
        audit: Arc::clone(&audit),
    });

    // Admin port: server routes at the root, the transfer API nested under /client, plus the web UI.
    let admin_router = api::router(Arc::clone(&server_app)).nest(
        "/client",
        pesit_client::api::router(Arc::clone(&client_app)),
    );
    // Transfer port: the transfer API at the root, for tools that expect the standalone client API.
    let transfer_router = pesit_client::api::router(client_app);

    let admin_addr = format!("{}:{}", opts.api_bind, opts.api_port);
    let transfer_addr = format!("{}:{}", opts.api_bind, opts.transfer_port);
    let admin = tokio::net::TcpListener::bind(&admin_addr)
        .await
        .with_context(|| format!("binding admin API on {admin_addr}"))?;
    let transfer = tokio::net::TcpListener::bind(&transfer_addr)
        .await
        .with_context(|| format!("binding transfer API on {transfer_addr}"))?;
    tracing::info!(
        "admin API + web UI on http://{admin_addr} · transfer API on http://{transfer_addr}"
    );

    let result = tokio::select! {
        r = axum::serve(admin, admin_router) => r.map_err(anyhow::Error::from),
        r = axum::serve(transfer, transfer_router) => r.map_err(anyhow::Error::from),
        () = shutdown_signal() => Ok(()),
    };
    manager.stop_all();
    result
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = ctrl_c => {},
            () = async { match term.as_mut() { Some(t) => { t.recv().await; } None => std::future::pending::<()>().await } } => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
    tracing::info!("shutting down");
}

fn register_cli_server(
    store: &JsonStore,
    mut server: cmodel::PesitServer,
) -> anyhow::Result<cmodel::PesitServer> {
    server.created_at = Some(now_iso());
    server.updated_at = Some(now_iso());
    store.put(cmodel::tables::SERVERS, &server.id, &server)?;
    Ok(server)
}

async fn wait_and_report(engine: &Engine, id: &str) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let Some(h) = engine.get(id).map_err(|e| anyhow::anyhow!(e.message))? else {
            anyhow::bail!("transfer {id} vanished")
        };
        if h.status.is_final() {
            println!("{}", serde_json::to_string_pretty(&h)?);
            if h.status != cmodel::TransferStatus::Completed {
                std::process::exit(1);
            }
            return Ok(());
        }
    }
}

fn bootstrap(store: &JsonStore, boot: Bootstrap) -> anyhow::Result<()> {
    for mut p in boot.partners {
        p.created_at.get_or_insert_with(now_iso);
        p.updated_at = Some(now_iso());
        store.put(tables::PARTNERS, &p.id.clone(), &p)?;
    }
    for mut f in boot.files {
        f.created_at.get_or_insert_with(now_iso);
        f.updated_at = Some(now_iso());
        store.put(tables::FILES, &f.id.clone(), &f)?;
    }
    for mut r in boot.remote_partners {
        r.created_at.get_or_insert_with(now_iso);
        store.put(tables::REMOTE_PARTNERS, &r.id.clone(), &r)?;
    }
    for mut s in boot.servers {
        if s.id.is_none() {
            s.id = Some(store.next_counter("server_id")?);
        }
        s.created_at.get_or_insert_with(now_iso);
        s.updated_at = Some(now_iso());
        store.put(tables::SERVERS, &s.server_id.clone(), &s)?;
    }
    Ok(())
}
