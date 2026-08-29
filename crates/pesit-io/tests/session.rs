//! In-process requester ↔ responder sessions over a duplex stream.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pesit_core::builder::FileSpec;
use pesit_core::params::{Compression, EndCode, RequestedAttributes, SyncOption};
use pesit_core::Diagnostic;
use pesit_io::checkpoint::{Checkpoint, CheckpointStore, MemoryCheckpoints};
use pesit_io::datapath::{Control, DataEnd, Progress};
use pesit_io::io::{ArticleSink, Position, VecSink, VecSource};
use pesit_io::requester::{Requester, RequesterConfig, TransferSpec};
use pesit_io::responder::{
    self, ConnectAccept, ConnectRequest, CreateAccept, Refusal, ResponderConfig, SelectAccept,
    ServerHandler, SessionInfo, TransferEvent,
};
use pesit_io::transport::Framing;
use pesit_io::SessionError;

/// Shared state of the test server.
#[derive(Default)]
struct Store {
    received: Mutex<Vec<(String, Vec<Vec<u8>>)>>,
    files: Mutex<Vec<(String, Vec<Vec<u8>>)>>,
    messages: Mutex<Vec<Vec<u8>>>,
    events: Mutex<Vec<String>>,
    checkpoints: Mutex<Option<MemoryCheckpoints>>,
    partial: Mutex<Option<SharedSink>>,
    cancel: Mutex<Option<tokio::sync::watch::Receiver<bool>>>,
}

/// A sink that keeps its content in the store so that a restarted transfer can resume.
#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<VecSink>>);

impl ArticleSink for SharedSink {
    fn write_article(&mut self, article: &[u8]) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .write_article(article)
    }
    fn checkpoint(&mut self) -> std::io::Result<Position> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .checkpoint()
    }
    fn truncate(&mut self, pos: Position) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .truncate(pos)
    }
    fn position(&self) -> Position {
        self.0.lock().map(|s| s.position()).unwrap_or_default()
    }
    fn finish(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .finish()
    }
}

/// Checkpoint store shared with the test (to simulate persistence across sessions).
struct SharedCheckpoints(Arc<Store>);

impl CheckpointStore for SharedCheckpoints {
    fn record(&mut self, cp: Checkpoint) -> std::io::Result<()> {
        self.0
            .checkpoints
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .get_or_insert_with(MemoryCheckpoints::new)
            .record(cp)
    }
    fn get(&self, sync: u32) -> Option<Checkpoint> {
        self.0.checkpoints.lock().ok()?.as_ref()?.get(sync)
    }
    fn last(&self) -> Option<Checkpoint> {
        self.0.checkpoints.lock().ok()?.as_ref()?.last()
    }
    fn last_acknowledged(&self) -> Option<Checkpoint> {
        self.0
            .checkpoints
            .lock()
            .ok()?
            .as_ref()?
            .last_acknowledged()
    }
    fn acknowledge(&mut self, sync: u32) -> std::io::Result<()> {
        self.0
            .checkpoints
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .get_or_insert_with(MemoryCheckpoints::new)
            .acknowledge(sync)
    }
    fn clear(&mut self) -> std::io::Result<()> {
        *self
            .0
            .checkpoints
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))? = None;
        Ok(())
    }
}

/// Checkpoint store shared between two client sessions.
struct Cps(Arc<Mutex<MemoryCheckpoints>>);
impl CheckpointStore for Cps {
    fn record(&mut self, cp: Checkpoint) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .record(cp)
    }
    fn get(&self, sync: u32) -> Option<Checkpoint> {
        self.0.lock().ok()?.get(sync)
    }
    fn last(&self) -> Option<Checkpoint> {
        self.0.lock().ok()?.last()
    }
    fn last_acknowledged(&self) -> Option<Checkpoint> {
        self.0.lock().ok()?.last_acknowledged()
    }
    fn acknowledge(&mut self, sync: u32) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .acknowledge(sync)
    }
    fn clear(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .clear()
    }
}

struct TestServer {
    store: Arc<Store>,
    accept: ConnectAccept,
    password: Option<String>,
}

impl ServerHandler for TestServer {
    fn authenticate(&self, req: &ConnectRequest) -> Result<ConnectAccept, Refusal> {
        if req.requester != "CLIENT" {
            return Err(Refusal::new(Diagnostic::CALLER_UNKNOWN));
        }
        if self.password.is_some() && req.password != self.password {
            return Err(Refusal::with_message(
                Diagnostic::CALLER_NOT_AUTHORISED,
                "bad password",
            ));
        }
        Ok(self.accept.clone())
    }

    fn create(&self, _session: &SessionInfo, file: &FileSpec) -> Result<CreateAccept, Refusal> {
        if file.file_name == "REFUSED" {
            return Err(Refusal::with_message(
                Diagnostic::TRANSFER_REFUSED,
                "no thanks",
            ));
        }
        let (sink, restart) = if file.restarted {
            let sink = self
                .store
                .partial
                .lock()
                .ok()
                .and_then(|p| p.clone())
                .unwrap_or_default();
            let restart = self
                .store
                .checkpoints
                .lock()
                .ok()
                .and_then(|c| c.as_ref().and_then(CheckpointStore::last));
            (sink, restart)
        } else {
            (SharedSink::default(), None)
        };
        if let Ok(mut p) = self.store.partial.lock() {
            *p = Some(sink.clone());
        }
        Ok(CreateAccept {
            sink: Box::new(sink),
            checkpoints: Box::new(SharedCheckpoints(Arc::clone(&self.store))),
            transfer_id: Some(42),
            restart,
            max_article: 0,
            handle: 1,
            free_message: None,
        })
    }

    fn select(
        &self,
        _session: &SessionInfo,
        file: &FileSpec,
        _attrs: RequestedAttributes,
    ) -> Result<SelectAccept, Refusal> {
        let files = self
            .store
            .files
            .lock()
            .map_err(|_| Refusal::new(Diagnostic::SYSTEM_ERROR))?;
        let Some((_, articles)) = files.iter().find(|(n, _)| *n == file.file_name) else {
            return Err(Refusal::new(Diagnostic::FILE_NOT_FOUND));
        };
        let mut spec = file.clone();
        spec.article_length = articles.iter().map(Vec::len).max().unwrap_or(0) as u16;
        spec.label = Some("served".into());
        Ok(SelectAccept {
            source: Box::new(VecSource::new(articles.clone())),
            checkpoints: Box::new(SharedCheckpoints(Arc::clone(&self.store))),
            spec,
            handle: 2,
        })
    }

    fn message(
        &self,
        _session: &SessionInfo,
        _file: &FileSpec,
        message: &[u8],
        expects_reply: bool,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        if let Ok(mut m) = self.store.messages.lock() {
            m.push(message.to_vec());
        }
        Ok(expects_reply.then(|| b"REPLY".to_vec()))
    }

    fn transfer_event(&self, _session: &SessionInfo, handle: u64, event: TransferEvent) {
        let text = match event {
            TransferEvent::Started { transfer_id, from } => {
                format!("started {transfer_id} from sync {}", from.sync)
            }
            TransferEvent::Progress(_) => return,
            TransferEvent::Ended { data, diag } => {
                if handle == 1 && data.end == DataEnd::Completed && diag.is_ok() {
                    if let (Ok(p), Ok(mut r)) =
                        (self.store.partial.lock(), self.store.received.lock())
                    {
                        if let Some(sink) = p.as_ref() {
                            r.push((
                                "received".into(),
                                sink.0
                                    .lock()
                                    .map(|s| s.articles.clone())
                                    .unwrap_or_default(),
                            ));
                        }
                    }
                }
                format!("ended {:?} {}", data.end, diag)
            }
            TransferEvent::Failed(e) => format!("failed {e}"),
        };
        if let Ok(mut ev) = self.store.events.lock() {
            ev.push(text);
        }
    }

    fn session_closed(&self, _session: &SessionInfo, error: Option<&SessionError>) {
        if let Ok(mut ev) = self.store.events.lock() {
            ev.push(format!("closed {error:?}"));
        }
    }

    fn cancel_flag(
        &self,
        _session: &SessionInfo,
        _handle: u64,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.store.cancel.lock().ok().and_then(|c| c.clone())
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn client_config() -> RequesterConfig {
    init_tracing();
    RequesterConfig {
        requester_id: "CLIENT".into(),
        server_id: "SERVER".into(),
        timeout: Duration::from_secs(5),
        ..RequesterConfig::default()
    }
}

/// Start a server session over a duplex pipe and connect a requester to it.
async fn session(
    store: Arc<Store>,
    accept: ConnectAccept,
    cfg: RequesterConfig,
    password: Option<String>,
) -> (
    Result<Requester, SessionError>,
    tokio::task::JoinHandle<Result<(), SessionError>>,
) {
    let (a, b) = tokio::io::duplex(1 << 16);
    let handler: Arc<dyn ServerHandler> = Arc::new(TestServer {
        store,
        accept,
        password,
    });
    let rc = ResponderConfig {
        session_id: "s1".into(),
        conn_id: 7,
        timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        remote_addr: "duplex".into(),
    };
    let server = tokio::spawn(responder::serve(
        Box::pin(b),
        Framing::LengthPrefixed,
        rc,
        handler,
    ));
    let client = Requester::connect(Box::pin(a), Framing::LengthPrefixed, cfg).await;
    (client, server)
}

fn articles(n: usize, len: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|i| (0..len).map(|j| ((i * 7 + j) % 251) as u8).collect())
        .collect()
}

fn no_progress(_: Progress) {}

#[tokio::test]
async fn write_then_read_round_trip() {
    let store = Arc::new(Store::default());
    let (client, server) = session(
        Arc::clone(&store),
        ConnectAccept::default(),
        client_config(),
        None,
    )
    .await;
    let mut client = client.unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        client.negotiated().sync,
        SyncOption {
            interval_kb: 32,
            window: 4
        }
    );
    assert!(client.negotiated().resync);

    let data = articles(500, 1000); // 500 KB → ~15 sync points
    let mut source = VecSource::new(data.clone());
    let mut cps = MemoryCheckpoints::new();
    let mut progress = no_progress;
    let mut ctrl = Control {
        cancel: None,
        progress: &mut progress,
    };
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "FILE1".into(),
            file_type: 1,
            article_length: 1000,
            ..FileSpec::default()
        },
        restart: None,
    };
    let out = client
        .send_file(&spec, &mut source, &mut cps, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(out.is_complete(), "{out:?}");
    assert_eq!(out.transfer_id, 42);
    assert_eq!(out.data.data_bytes, 500_000);
    assert_eq!(out.data.articles, 500);
    assert_eq!(out.data.last_sync, 15);
    assert_eq!(store.received.lock().map_or(0, |r| r.len()), 1);
    assert_eq!(
        store
            .received
            .lock()
            .ok()
            .and_then(|r| r.first().map(|f| f.1.clone())),
        Some(data.clone())
    );

    // read it back
    if let Ok(mut f) = store.files.lock() {
        f.push(("FILE1".into(), data.clone()));
    }
    let mut sink = VecSink::new();
    let mut cps = MemoryCheckpoints::new();
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "FILE1".into(),
            file_type: 1,
            ..FileSpec::default()
        },
        restart: None,
    };
    let out = client
        .receive_file(&spec, &mut sink, &mut cps, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(out.is_complete(), "{out:?}");
    assert_eq!(out.remote.label.as_deref(), Some("served"));
    assert_eq!(out.remote.article_length, 1000);
    assert_eq!(sink.articles, data);
    assert!(sink.finished);

    // message
    let m = client
        .send_message(
            &FileSpec {
                file_name: "MSG".into(),
                ..FileSpec::default()
            },
            b"hello",
            true,
        )
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(m.reply.as_deref(), Some(&b"REPLY"[..]));
    assert_eq!(
        store.messages.lock().map(|m| m.clone()).unwrap_or_default(),
        vec![b"hello".to_vec()]
    );

    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    let events = store.events.lock().map(|e| e.clone()).unwrap_or_default();
    assert_eq!(events.last().map(String::as_str), Some("closed None"));
    assert!(
        events.iter().any(|e| e == "started 42 from sync 0"),
        "{events:?}"
    );
}

#[tokio::test]
async fn crc_compression_and_windowless_sync() {
    let store = Arc::new(Store::default());
    let cfg = RequesterConfig {
        crc: true,
        compression: Compression::Mixed,
        sync: SyncOption {
            interval_kb: 4,
            window: 0,
        },
        ..client_config()
    };
    let accept = ConnectAccept {
        compression: Compression::Mixed,
        sync: SyncOption {
            interval_kb: 64,
            window: 0,
        },
        ..ConnectAccept::default()
    };
    let (client, server) = session(Arc::clone(&store), accept, cfg, None).await;
    let mut client = client.unwrap_or_else(|e| panic!("{e}"));
    assert!(client.negotiated().crc);
    assert_eq!(
        client.negotiated().sync,
        SyncOption {
            interval_kb: 4,
            window: 0
        }
    );

    // highly compressible text-like articles of varying lengths
    let data: Vec<Vec<u8>> = (0..200)
        .map(|i| format!("{:0>60}-line-{i}-{}", i % 7, "x".repeat(i % 40)).into_bytes())
        .collect();
    let mut source = VecSource::new(data.clone());
    let mut cps = MemoryCheckpoints::new();
    let mut progress = no_progress;
    let mut ctrl = Control {
        cancel: None,
        progress: &mut progress,
    };
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "TEXT".into(),
            article_length: 120,
            ..FileSpec::default()
        },
        restart: None,
    };
    let out = client
        .send_file(&spec, &mut source, &mut cps, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(out.is_complete(), "{out:?}");
    assert!(
        out.data.data_bytes < 200 * 60,
        "compression should reduce the byte count: {}",
        out.data.data_bytes
    );
    assert_eq!(
        store
            .received
            .lock()
            .ok()
            .and_then(|r| r.first().map(|f| f.1.clone())),
        Some(data)
    );
    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
}

#[tokio::test]
async fn cancel_and_restart_write() {
    let store = Arc::new(Store::default());
    let (tx, rx) = tokio::sync::watch::channel(false);
    let data = articles(300, 1000);
    // first attempt: cancelled by the requester after ~100 KB
    let (client, server) = session(
        Arc::clone(&store),
        ConnectAccept::default(),
        client_config(),
        None,
    )
    .await;
    let mut client = client.unwrap_or_else(|e| panic!("{e}"));
    let mut source = VecSource::new(data.clone());
    let cps = Arc::new(Mutex::new(MemoryCheckpoints::new()));
    let mut local = Cps(Arc::clone(&cps));
    let mut progress = move |p: Progress| {
        if p.data_bytes >= 100_000 {
            let _ = tx.send(true);
        }
    };
    let mut ctrl = Control {
        cancel: Some(rx),
        progress: &mut progress,
    };
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "BIG".into(),
            article_length: 1000,
            transfer_id: 5,
            ..FileSpec::default()
        },
        restart: None,
    };
    let out = client
        .send_file(&spec, &mut source, &mut local, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(
            out.data.end,
            DataEnd::Interrupted {
                code: EndCode::CancelByRequester,
                by_peer: false,
                ..
            }
        ),
        "{out:?}"
    );
    assert!(out.data.data_bytes >= 100_000 && out.data.data_bytes < 300_000);
    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    let server_last = store
        .checkpoints
        .lock()
        .ok()
        .and_then(|c| c.as_ref().and_then(CheckpointStore::last))
        .unwrap_or_default();
    assert!(server_last.sync >= 2, "server checkpoints: {server_last:?}");
    let local_acked = local.last_acknowledged().unwrap_or_default();
    assert!(local_acked.sync >= 1);

    // second attempt: restart
    let (client, server) = session(
        Arc::clone(&store),
        ConnectAccept::default(),
        client_config(),
        None,
    )
    .await;
    let mut client = client.unwrap_or_else(|e| panic!("{e}"));
    let mut source = VecSource::new(data.clone());
    let mut progress = no_progress;
    let mut ctrl = Control {
        cancel: None,
        progress: &mut progress,
    };
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "BIG".into(),
            article_length: 1000,
            transfer_id: 5,
            ..FileSpec::default()
        },
        restart: Some(local_acked),
    };
    let out = client
        .send_file(&spec, &mut source, &mut local, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(out.is_complete(), "{out:?}");
    assert_eq!(out.started_from.sync, server_last.sync);
    assert_eq!(out.data.data_bytes, 300_000);
    assert_eq!(out.data.articles, 300);
    assert_eq!(
        store
            .received
            .lock()
            .ok()
            .and_then(|r| r.last().map(|f| f.1.clone())),
        Some(data)
    );
    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
    let events = store.events.lock().map(|e| e.clone()).unwrap_or_default();
    assert!(
        events
            .iter()
            .any(|e| e == &format!("started 42 from sync {}", server_last.sync)),
        "{events:?}"
    );
}

#[tokio::test]
async fn refusals() {
    let store = Arc::new(Store::default());
    // wrong requester id → RCONNECT
    let cfg = RequesterConfig {
        requester_id: "NOBODY".into(),
        ..client_config()
    };
    let (client, server) = session(Arc::clone(&store), ConnectAccept::default(), cfg, None).await;
    match client {
        Err(SessionError::Refused { diag, .. }) => assert_eq!(diag, Diagnostic::CALLER_UNKNOWN),
        other => panic!("expected RCONNECT, got {:?}", other.err()),
    }
    assert!(matches!(
        server.await.unwrap_or_else(|e| panic!("{e}")),
        Err(SessionError::Refused { .. })
    ));

    // bad password
    let (client, server) = session(
        Arc::clone(&store),
        ConnectAccept::default(),
        client_config(),
        Some("secret".into()),
    )
    .await;
    match client {
        Err(SessionError::Refused { diag, message, .. }) => {
            assert_eq!(diag, Diagnostic::CALLER_NOT_AUTHORISED);
            assert_eq!(message.as_deref(), Some("bad password"));
        }
        other => panic!("expected RCONNECT, got {:?}", other.err()),
    }
    let _ = server.await;

    // refused CREATE and unknown SELECT, session continues
    let (client, server) = session(
        Arc::clone(&store),
        ConnectAccept::default(),
        client_config(),
        None,
    )
    .await;
    let mut client = client.unwrap_or_else(|e| panic!("{e}"));
    let mut progress = no_progress;
    let mut ctrl = Control {
        cancel: None,
        progress: &mut progress,
    };
    let mut cps = MemoryCheckpoints::new();
    let mut source = VecSource::new(articles(1, 10));
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "REFUSED".into(),
            ..FileSpec::default()
        },
        restart: None,
    };
    match client
        .send_file(&spec, &mut source, &mut cps, &mut ctrl)
        .await
    {
        Err(SessionError::Refused { diag, message, .. }) => {
            assert_eq!(diag, Diagnostic::TRANSFER_REFUSED);
            assert_eq!(message.as_deref(), Some("no thanks"));
        }
        other => panic!("expected refusal, got {other:?}"),
    }
    let mut sink = VecSink::new();
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "MISSING".into(),
            ..FileSpec::default()
        },
        restart: None,
    };
    match client
        .receive_file(&spec, &mut sink, &mut cps, &mut ctrl)
        .await
    {
        Err(SessionError::Refused { diag, .. }) => assert_eq!(diag, Diagnostic::FILE_NOT_FOUND),
        other => panic!("expected refusal, got {other:?}"),
    }
    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
}

#[tokio::test]
async fn preconnect_and_raw_framing() {
    let store = Arc::new(Store::default());
    let (a, b) = tokio::io::duplex(1 << 16);
    let handler: Arc<dyn ServerHandler> = Arc::new(TestServer {
        store: Arc::clone(&store),
        accept: ConnectAccept::default(),
        password: None,
    });
    let rc = ResponderConfig {
        session_id: "s2".into(),
        conn_id: 9,
        timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(5),
        remote_addr: "duplex".into(),
    };
    let server = tokio::spawn(responder::serve(Box::pin(b), Framing::Raw, rc, handler));
    let cfg = RequesterConfig {
        preconnect: Some(pesit_io::requester::Preconnect {
            identifier: "CLIENT".into(),
            password: "PWD".into(),
        }),
        crc: true,
        ..client_config()
    };
    let mut client = Requester::connect(Box::pin(a), Framing::Raw, cfg)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let data = articles(20, 3000);
    let mut source = VecSource::new(data.clone());
    let mut cps = MemoryCheckpoints::new();
    let mut progress = no_progress;
    let mut ctrl = Control {
        cancel: None,
        progress: &mut progress,
    };
    let spec = TransferSpec {
        file: FileSpec {
            file_name: "RAW".into(),
            article_length: 3000,
            ..FileSpec::default()
        },
        restart: None,
    };
    let out = client
        .send_file(&spec, &mut source, &mut cps, &mut ctrl)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(out.is_complete(), "{out:?}");
    assert_eq!(
        store
            .received
            .lock()
            .ok()
            .and_then(|r| r.first().map(|f| f.1.clone())),
        Some(data)
    );
    client.release().await.unwrap_or_else(|e| panic!("{e}"));
    server
        .await
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|e| panic!("{e}"));
}
