//! Certificate and CA management wired into the node: an on-disk certificate store, an optional
//! local CA, and an optional native HashiCorp Vault PKI backend. Exposed under `/api/v1/certificates`
//! and usable by the TLS layer (listeners and remote servers may reference a keystore / truststore
//! by name).

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_pki::{ca::LocalCa, cert, provider::CertRequest, CertStore, VaultConfig, VaultPki};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Mutex as StdMutex;
use tokio::sync::Mutex;

use crate::api::App;

const PKI_TABLE: &str = "pki";
const VAULT_KEY: &str = "vault";

/// Certificate/CA state.
pub struct PkiState {
    dir: PathBuf,
    store: CertStore,
    ca: StdMutex<Option<LocalCa>>,
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
            ca: StdMutex::new(ca),
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

    /// Export the CA, keystores and truststores as a JSON value (for backups). Contains private keys.
    #[must_use]
    pub fn export_material(&self) -> serde_json::Value {
        let (cert_path, key_path) = self.ca_files();
        let ca = match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(cert), Ok(key)) => json!({ "certificate": cert, "privateKey": key }),
            _ => serde_json::Value::Null,
        };
        let keystores: Vec<serde_json::Value> = self
            .store
            .list_keystores()
            .into_iter()
            .filter_map(|m| {
                let (cp, kp) = self.store.keystore_files(&m.name)?;
                let (cert, key) = (
                    std::fs::read_to_string(cp).ok()?,
                    std::fs::read_to_string(kp).ok()?,
                );
                Some(json!({ "name": m.name, "certificate": cert, "privateKey": key }))
            })
            .collect();
        let truststores: Vec<serde_json::Value> = self
            .store
            .list_truststores()
            .into_iter()
            .filter_map(|m| {
                let bundle = std::fs::read_to_string(self.store.truststore_file(&m.name)?).ok()?;
                Some(json!({ "name": m.name, "certificates": bundle }))
            })
            .collect();
        json!({ "ca": ca, "keystores": keystores, "truststores": truststores })
    }

    /// The list of revoked (serial, time) entries.
    #[must_use]
    pub fn revoked_list(&self) -> Vec<RevokedEntry> {
        self.doc
            .get::<Vec<RevokedEntry>>(PKI_TABLE, "revoked")
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    /// Record a certificate serial (hex, colons/spaces ignored) as revoked.
    pub fn revoke(&self, serial: &str) -> Result<(), pesit_pki::PkiError> {
        let norm = normalize_serial(serial);
        if norm.is_empty() {
            return Err(pesit_pki::PkiError::Gen("invalid serial".into()));
        }
        let mut list = self.revoked_list();
        if !list.iter().any(|e| e.serial == norm) {
            list.push(RevokedEntry {
                serial: norm,
                revoked_at: pesit_app::time::now_iso(),
            });
            self.doc
                .put(PKI_TABLE, "revoked", &list)
                .map_err(|e| pesit_pki::PkiError::Gen(e.to_string()))?;
        }
        Ok(())
    }

    /// Build a CRL (PEM) signed by the local CA covering the revoked serials.
    pub fn build_crl(&self) -> Result<String, pesit_pki::PkiError> {
        let ca = self
            .ca
            .lock()
            .map_err(|_| pesit_pki::PkiError::Gen("CA lock poisoned".into()))?
            .clone()
            .ok_or(pesit_pki::PkiError::NoCa)?;
        let revoked: Vec<(Vec<u8>, i64)> = self
            .revoked_list()
            .into_iter()
            .filter_map(|e| {
                let bytes = hex_to_bytes(&e.serial)?;
                let at = pesit_app::time::parse_millis(&e.revoked_at).map_or(0, |ms| ms / 1000);
                Some((bytes, at))
            })
            .collect();
        let number = self.doc.next_counter("crl_number").unwrap_or(1);
        ca.sign_crl(&revoked, number, 7)
    }

    /// Sign arbitrary bytes with the local CA key (ECDSA P-256), if a CA is configured.
    #[must_use]
    pub fn sign_data(&self, data: &[u8]) -> Option<Vec<u8>> {
        let ca = self.ca.lock().ok()?.clone()?;
        pesit_pki::sign::sign_bytes(&ca, data).ok()
    }

    /// Answer an OCSP request (DER) about certificates issued by the local CA; returns the
    /// DER-encoded, CA-signed OCSP response.
    pub fn ocsp_respond(&self, request_der: &[u8]) -> Result<Vec<u8>, pesit_pki::PkiError> {
        let ca = self
            .ca
            .lock()
            .map_err(|_| pesit_pki::PkiError::Gen("CA lock poisoned".into()))?
            .clone()
            .ok_or(pesit_pki::PkiError::NoCa)?;
        let revoked: Vec<pesit_pki::ocsp::Revoked> = self
            .revoked_list()
            .into_iter()
            .map(|e| pesit_pki::ocsp::Revoked {
                revoked_at_unix: pesit_app::time::parse_millis(&e.revoked_at)
                    .map_or(0, |ms| ms / 1000),
                serial_hex: e.serial,
            })
            .collect();
        let now = pesit_app::time::now_millis() / 1000;
        pesit_pki::ocsp::respond(&ca, &revoked, request_der, now)
    }

    /// Names of keystores whose certificate expires within `days`.
    #[must_use]
    pub fn expiring_keystores(&self, days: i64) -> Vec<String> {
        let horizon = pesit_app::time::now_millis() + days * 86_400_000;
        self.store
            .list_keystores()
            .into_iter()
            .filter(|m| rfc2822_millis(&m.info.not_after).is_some_and(|ms| ms <= horizon))
            .map(|m| m.name)
            .collect()
    }

    /// Re-issue a keystore in place, keeping its identity (CN / SANs) and recorded backend.
    pub async fn rotate(&self, name: &str) -> Result<(), pesit_pki::PkiError> {
        let current = self
            .store
            .keystore(name)
            .ok_or_else(|| pesit_pki::PkiError::Gen(format!("keystore '{name}' not found")))?;
        let meta = self
            .doc
            .get::<serde_json::Value>(PKI_TABLE, &format!("ks:{name}"))
            .ok()
            .flatten();
        let backend = meta
            .as_ref()
            .and_then(|m| m.get("backend"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("local")
            .to_owned();
        let common_name = meta
            .as_ref()
            .and_then(|m| m.get("commonName"))
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| cn_of(&current.info.subject), str::to_owned);
        let sans: Vec<String> = meta
            .as_ref()
            .and_then(|m| m.get("sans"))
            .and_then(serde_json::Value::as_array)
            .map_or_else(
                || current.info.sans.clone(),
                |a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                },
            );
        let ttl = meta
            .as_ref()
            .and_then(|m| m.get("ttlDays"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(365) as u32;
        let req = CertRequest {
            common_name,
            sans,
            ttl_days: ttl,
            is_ca: false,
            server_auth: true,
            client_auth: true,
            organization: None,
        };
        let issued = self.issue_via(&backend, &req).await?;
        let key = issued
            .private_key
            .ok_or_else(|| pesit_pki::PkiError::Gen("no private key returned".into()))?;
        self.store
            .put_keystore(name, &issued.certificate, &key)
            .map_err(|e| pesit_pki::PkiError::Gen(e.to_string()))?;
        tracing::info!("rotated keystore '{name}' (backend {backend})");
        Ok(())
    }

    async fn issue_via(
        &self,
        backend: &str,
        req: &CertRequest,
    ) -> Result<pesit_pki::Issued, pesit_pki::PkiError> {
        if backend.eq_ignore_ascii_case("vault") {
            let v =
                self.vault.lock().await.clone().ok_or_else(|| {
                    pesit_pki::PkiError::Vault("no Vault backend configured".into())
                })?;
            v.issue(req).await
        } else {
            let ca = self
                .ca
                .lock()
                .map_err(|_| pesit_pki::PkiError::Gen("CA lock poisoned".into()))?
                .clone()
                .ok_or(pesit_pki::PkiError::NoCa)?;
            ca.issue(req)
        }
    }

    /// Import CA / keystores / truststores from a backup value.
    pub fn import_material(&self, value: &serde_json::Value) -> Result<(), pesit_pki::PkiError> {
        if let Some(ca) = value.get("ca").filter(|c| c.is_object()) {
            if let (Some(cert), Some(key)) = (
                ca.get("certificate").and_then(serde_json::Value::as_str),
                ca.get("privateKey").and_then(serde_json::Value::as_str),
            ) {
                let (cert_path, key_path) = self.ca_files();
                std::fs::write(cert_path, cert)?;
                write_private(&key_path, key)?;
                *self
                    .ca
                    .lock()
                    .map_err(|_| pesit_pki::PkiError::Gen("CA lock poisoned".into()))? =
                    Some(LocalCa::from_pem(cert.to_owned(), key.to_owned()));
            }
        }
        for k in value
            .get("keystores")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(name), Some(cert), Some(key)) = (
                k.get("name").and_then(serde_json::Value::as_str),
                k.get("certificate").and_then(serde_json::Value::as_str),
                k.get("privateKey").and_then(serde_json::Value::as_str),
            ) {
                self.store
                    .put_keystore(name, cert, key)
                    .map_err(|e| pesit_pki::PkiError::Gen(e.to_string()))?;
            }
        }
        for t in value
            .get("truststores")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(name), Some(bundle)) = (
                t.get("name").and_then(serde_json::Value::as_str),
                t.get("certificates").and_then(serde_json::Value::as_str),
            ) {
                self.store
                    .put_truststore(name, bundle)
                    .map_err(|e| pesit_pki::PkiError::Gen(e.to_string()))?;
            }
        }
        Ok(())
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
        .route("/api/v1/certificates/revoked", get(revoked).post(revoke))
        .route("/api/v1/certificates/crl", get(crl))
        .route(
            "/api/v1/certificates/keystores/{name}/rotate",
            post(rotate_keystore),
        )
}

/// Open OCSP responder routes. These are merged into the router *outside* the API-key layer,
/// because OCSP clients are unauthenticated. Serves the local CA's revocation status (RFC 6960).
pub fn ocsp_routes() -> Router<Arc<App>> {
    Router::new()
        .route("/ocsp", post(ocsp_post))
        .route("/ocsp/{req}", get(ocsp_get))
}

async fn ocsp_post(State(app): State<Arc<App>>, body: axum::body::Bytes) -> Response {
    ocsp_reply(&app, &body)
}

async fn ocsp_get(State(app): State<Arc<App>>, Path(req): Path<String>) -> Response {
    use base64::Engine;
    // OCSP-over-GET carries the base64 of the DER request (percent-decoding done by the router).
    match base64::engine::general_purpose::STANDARD.decode(req.as_bytes()) {
        Ok(der) => ocsp_reply(&app, &der),
        Err(_) => (StatusCode::BAD_REQUEST, "invalid base64 OCSP request").into_response(),
    }
}

fn ocsp_reply(app: &App, request_der: &[u8]) -> Response {
    let Some(pki) = app.pki.as_deref() else {
        return (
            StatusCode::NOT_FOUND,
            "certificate management is not enabled",
        )
            .into_response();
    };
    match pki.ocsp_respond(request_der) {
        Ok(der) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "application/ocsp-response",
            )],
            der,
        )
            .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
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
    *state
        .ca
        .lock()
        .map_err(|_| ApiError::internal("CA lock poisoned"))? = Some(ca);
    app.audit
        .success("certificate", "generate-ca", &b.common_name);
    tracing::info!("generated local CA '{}'", b.common_name);
    Ok(Json(info))
}
async fn get_ca(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    let guard = state
        .ca
        .lock()
        .map_err(|_| ApiError::internal("CA lock poisoned"))?;
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
        let ca = state
            .ca
            .lock()
            .map_err(|_| ApiError::internal("CA lock poisoned"))?
            .clone()
            .ok_or_else(|| ApiError::bad_request("no local CA configured — generate one first"))?;
        (ca.issue(&b.request).map_err(map_pki)?, "local")
    };
    let stored_as = if let (Some(name), Some(key)) = (&b.store_as, &issued.private_key) {
        state
            .store
            .put_keystore(name, &issued.certificate, key)
            .map_err(map_store)?;
        let meta = serde_json::json!({
            "backend": kind, "commonName": b.request.common_name, "sans": b.request.sans,
            "ttlDays": b.request.ttl_days, "serverAuth": b.request.server_auth, "clientAuth": b.request.client_auth,
        });
        let _ = state.doc.put(PKI_TABLE, &format!("ks:{name}"), &meta);
        Some(name.clone())
    } else {
        None
    };
    app.audit.success(
        "certificate",
        "issue",
        format!("{} ({kind})", b.request.common_name),
    );
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

/// A revoked-certificate record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokedEntry {
    /// Serial number (hex).
    pub serial: String,
    /// Revocation time (RFC 3339).
    pub revoked_at: String,
}

fn normalize_serial(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_hexdigit)
        .flat_map(char::to_lowercase)
        .collect()
}
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let h = normalize_serial(hex);
    if h.is_empty() || h.len() % 2 != 0 {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
        .collect()
}
fn cn_of(subject: &str) -> String {
    subject
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("CN="))
        .unwrap_or(subject)
        .to_owned()
}
fn rfc2822_millis(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc2822(s)
        .ok()
        .map(|d| d.timestamp_millis())
}

#[derive(Deserialize)]
struct RevokeBody {
    serial: String,
}
async fn revoke(
    State(app): State<Arc<App>>,
    Json(b): Json<RevokeBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    state.revoke(&b.serial).map_err(map_pki)?;
    app.audit.success("certificate", "revoke", &b.serial);
    Ok(Json(json!({ "revoked": normalize_serial(&b.serial) })))
}
async fn revoked(State(app): State<Arc<App>>) -> Result<Json<Vec<RevokedEntry>>, ApiError> {
    Ok(Json(pki(&app)?.revoked_list()))
}
async fn crl(State(app): State<Arc<App>>) -> Result<Json<serde_json::Value>, ApiError> {
    let pem = pki(&app)?.build_crl().map_err(map_pki)?;
    Ok(Json(json!({ "crl": pem })))
}
async fn rotate_keystore(
    State(app): State<Arc<App>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let state = pki(&app)?;
    state.rotate(&name).await.map_err(map_pki)?;
    app.audit.success("certificate", "rotate", &name);
    let info = state.store.keystore(&name).map(|m| m.info);
    Ok(Json(json!({ "rotated": name, "info": info })))
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
