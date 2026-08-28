//! Certificate and CA management wired into the node: an on-disk certificate store, an optional
//! local CA, and an optional native HashiCorp Vault PKI backend. Exposed under `/api/v1/certificates`
//! and usable by the TLS layer (listeners and remote servers may reference a keystore / truststore
//! by name).

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_pki::{ca::LocalCa, cert, provider::CertRequest, CertStore, VaultConfig, VaultPki};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::api::App;

const PKI_TABLE: &str = "pki";
const VAULT_KEY: &str = "vault";

/// Certificate/CA state.
pub struct PkiState {
    dir: PathBuf,
    store: CertStore,
    ca: Mutex<Option<LocalCa>>,
    vault: Mutex<Option<Arc<VaultPki>>>,
    doc: Arc<JsonStore>,
}

fn map_pki(e: pesit_pki::PkiError) -> ApiError {
    match e {
        pesit_pki::PkiError::NoCa => {
            ApiError::bad_request("no local CA configured — generate one first")
        }
        pesit_pki::PkiError::Vault(m) => ApiError::bad_request(format!("vault: {m}")),
        other => ApiError::internal(other),
    }
}
fn map_store(e: pesit_pki::store::StoreError) -> ApiError {
    match e {
        pesit_pki::store::StoreError::Name(n) => {
            ApiError::bad_request(format!("invalid name '{n}'"))
        }
        pesit_pki::store::StoreError::MissingKey => {
            ApiError::bad_request("a keystore needs both a certificate and a private key")
        }
        pesit_pki::store::StoreError::Cert(c) => ApiError::bad_request(c.to_string()),
        pesit_pki::store::StoreError::Io(e) => ApiError::internal(e),
    }
}

impl PkiState {
    /// Open the state under `dir`, loading a persisted local CA and Vault configuration.
    pub fn open(dir: PathBuf, doc: Arc<JsonStore>) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let store = CertStore::open(&dir)?;
        doc.ensure_table(PKI_TABLE)?;
        let ca = load_ca(&dir);
        let vault = doc
            .get::<VaultConfig>(PKI_TABLE, VAULT_KEY)
            .ok()
            .flatten()
            .and_then(|cfg| VaultPki::new(cfg).map(Arc::new).ok());
        Ok(Self {
            dir,
            store,
            ca: Mutex::new(ca),
            vault: Mutex::new(vault),
            doc,
        })
    }

    fn ca_files(&self) -> (PathBuf, PathBuf) {
        (self.dir.join("ca.crt.pem"), self.dir.join("ca.key.pem"))
    }

    /// Resolve a keystore name to its certificate and key file paths.
    #[must_use]
    pub fn keystore_files(&self, name: &str) -> Option<(PathBuf, PathBuf)> {
        self.store.keystore_files(name)
    }

    /// Resolve a truststore name to its bundle file path.
    #[must_use]
    pub fn truststore_file(&self, name: &str) -> Option<PathBuf> {
        self.store.truststore_file(name)
    }
}

fn load_ca(dir: &std::path::Path) -> Option<LocalCa> {
    let cert = std::fs::read_to_string(dir.join("ca.crt.pem")).ok()?;
    let key = std::fs::read_to_string(dir.join("ca.key.pem")).ok()?;
    Some(LocalCa::from_pem(cert, key))
}

/// Routes for certificate management (merged into the admin router, so `X-API-Key` applies).
pub fn routes() -> Router<Arc<App>> {
    Router::new()
        .route("/api/v1/certificates/inspect", post(inspect))
        .route(
            "/api/v1/certificates/keystores",
            get(list_keystores).post(import_keystore),
        )
        .route(
            "/api/v1/certificates/keystores/{name}",
            get(get_keystore).delete(delete_keystore),
        )
        .route(
            "/api/v1/certificates/truststores",
            get(list_truststores).post(import_truststore),
        )
        .route(
            "/api/v1/certificates/truststores/{name}",
            get(get_truststore).delete(delete_truststore),
        )
        .route("/api/v1/certificates/ca", get(get_ca).post(generate_ca))
        .route("/api/v1/certificates/issue", post(issue))
        .route(
            "/api/v1/certificates/vault",
            get(vault_status).put(set_vault).delete(clear_vault),
        )
        .route("/api/v1/certificates/vault/test", post(test_vault))
}

fn pki(app: &App) -> Result<&PkiState, ApiError> {
    app.pki
        .as_deref()
        .ok_or_else(|| ApiError::internal("certificate management is not enabled"))
}

#[derive(Deserialize)]
struct InspectBody {
    pem: String,
}
async fn inspect(
    State(app): State<Arc<App>>,
    Json(body): Json<InspectBody>,
) -> Result<Json<Vec<cert::CertInfo>>, ApiError> {
    pki(&app)?;
    cert::inspect_all(body.pem.as_bytes())
        .map(Json)
        .map_err(|e| ApiError::bad_request(e.to_string()))
}

async fn list_keystores(
    State(app): State<Arc<App>>,
) -> Result<Json<Vec<pesit_pki::KeystoreMeta>>, ApiError> {
    Ok(Json(pki(&app)?.store.list_keystores()))
}
async fn get_keystore(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
) -> Result<Json<pesit_pki::KeystoreMeta>, ApiError> {
    pki(&app)?
        .store
        .keystore(&name)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("keystore '{name}' not found")))
}
async fn delete_keystore(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    if pki(&app)?.store.delete_keystore(&name).map_err(map_store)? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("keystore '{name}' not found")))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportKeystore {
    name: String,
    certificate: String,
    private_key: String,
}
async fn import_keystore(
    State(app): State<Arc<App>>,
    Json(b): Json<ImportKeystore>,
) -> Result<(StatusCode, Json<pesit_pki::KeystoreMeta>), ApiError> {
    let meta = pki(&app)?
        .store
        .put_keystore(&b.name, &b.certificate, &b.private_key)
        .map_err(map_store)?;
    Ok((StatusCode::CREATED, Json(meta)))
}

async fn list_truststores(
    State(app): State<Arc<App>>,
) -> Result<Json<Vec<pesit_pki::TruststoreMeta>>, ApiError> {
    Ok(Json(pki(&app)?.store.list_truststores()))
}
async fn get_truststore(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
) -> Result<Json<pesit_pki::TruststoreMeta>, ApiError> {
    pki(&app)?
        .store
        .truststore(&name)
        .map(Json)
        .ok_or_else(|| ApiError::not_found(format!("truststore '{name}' not found")))
}
async fn delete_truststore(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    if pki(&app)?
        .store
        .delete_truststore(&name)
        .map_err(map_store)?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!(
            "truststore '{name}' not found"
        )))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportTruststore {
    name: String,
    certificates: String,
}
async fn import_truststore(
    State(app): State<Arc<App>>,
    Json(b): Json<ImportTruststore>,
) -> Result<(StatusCode, Json<pesit_pki::TruststoreMeta>), ApiError> {
    let meta = pki(&app)?
        .store
        .put_truststore(&b.name, &b.certificates)
        .map_err(map_store)?;
    Ok((StatusCode::CREATED, Json(meta)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateCa {
    common_name: String,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default = "default_ca_ttl")]
    ttl_days: u32,
}
fn default_ca_ttl() -> u32 {
    3650
}
async fn generate_ca(
    State(app): State<Arc<App>>,
    Json(b): Json<GenerateCa>,
) -> Result<Json<cert::CertInfo>, ApiError> {
    let state = pki(&app)?;
    let ca = LocalCa::generate(&b.common_name, b.organization.as_deref(), b.ttl_days)
        .map_err(map_pki)?;
    let (cert_path, key_path) = state.ca_files();
    std::fs::write(&cert_path, ca.cert_pem())?;
    write_private(&key_path, ca.key_pem())?;
    let info = cert::inspect_pem(ca.cert_pem().as_bytes())
        .map_err(|e| ApiError::internal(e.to_string()))?;
    *state.ca.lock().await = Some(ca);
    tracing::info!("generated local CA '{}'", b.common_name);
    Ok(Json(info))
}
async fn get_ca(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    let guard = state.ca.lock().await;
    let Some(ca) = guard.as_ref() else {
        return Err(ApiError::not_found("no local CA configured"));
    };
    let info = cert::inspect_pem(ca.cert_pem().as_bytes())
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Json(json!({ "certificate": ca.cert_pem(), "info": info })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueBody {
    #[serde(flatten)]
    request: CertRequest,
    #[serde(default = "default_backend")]
    backend: String,
    #[serde(default)]
    store_as: Option<String>,
}
fn default_backend() -> String {
    "local".into()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueResult {
    #[serde(flatten)]
    issued: pesit_pki::Issued,
    backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored_as: Option<String>,
}
async fn issue(
    State(app): State<Arc<App>>,
    Json(b): Json<IssueBody>,
) -> Result<Json<IssueResult>, ApiError> {
    let state = pki(&app)?;
    let (issued, kind) = if b.backend == "vault" {
        let v = state
            .vault
            .lock()
            .await
            .clone()
            .ok_or_else(|| ApiError::bad_request("no Vault backend configured"))?;
        (v.issue(&b.request).await.map_err(map_pki)?, "vault")
    } else {
        let ca =
            state.ca.lock().await.clone().ok_or_else(|| {
                ApiError::bad_request("no local CA configured — generate one first")
            })?;
        (ca.issue(&b.request).map_err(map_pki)?, "local")
    };
    let stored_as = if let (Some(name), Some(key)) = (&b.store_as, &issued.private_key) {
        state
            .store
            .put_keystore(name, &issued.certificate, key)
            .map_err(map_store)?;
        Some(name.clone())
    } else {
        None
    };
    Ok(Json(IssueResult {
        backend: kind.to_owned(),
        issued,
        stored_as,
    }))
}

async fn vault_status(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    let cfg = state
        .doc
        .get::<VaultConfig>(PKI_TABLE, VAULT_KEY)
        .map_err(ApiError::from)?;
    let configured = cfg.is_some();
    Ok(Json(json!({
        "configured": configured,
        "address": cfg.as_ref().map(|c| c.address.clone()),
        "role": cfg.as_ref().map(|c| c.role.clone()),
        "mount": cfg.as_ref().and_then(|c| c.mount.clone()).unwrap_or_else(|| "pki".into()),
    })))
}
async fn set_vault(
    State(app): State<Arc<App>>,
    Json(cfg): Json<VaultConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    let vault = VaultPki::new(cfg.clone()).map_err(map_pki)?;
    let version = vault.health().await.map_err(map_pki)?;
    state.doc.put(PKI_TABLE, VAULT_KEY, &cfg)?;
    *state.vault.lock().await = Some(Arc::new(vault));
    tracing::info!(
        "Vault PKI backend configured at {} (mount {}, role {})",
        cfg.address,
        cfg.mount.as_deref().unwrap_or("pki"),
        cfg.role
    );
    Ok(Json(json!({ "configured": true, "vaultVersion": version })))
}
async fn clear_vault(State(app): State<Arc<App>>) -> Result<StatusCode, ApiError> {
    let state = pki(&app)?;
    state.doc.delete(PKI_TABLE, VAULT_KEY)?;
    *state.vault.lock().await = None;
    Ok(StatusCode::NO_CONTENT)
}
async fn test_vault(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    let v = state
        .vault
        .lock()
        .await
        .clone()
        .ok_or_else(|| ApiError::bad_request("no Vault backend configured"))?;
    match v.health().await {
        Ok(version) => Ok(Json(json!({ "success": true, "vaultVersion": version }))),
        Err(e) => Ok(Json(json!({ "success": false, "message": e.to_string() }))),
    }
}

#[cfg(unix)]
fn write_private(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}
#[cfg(not(unix))]
fn write_private(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}
