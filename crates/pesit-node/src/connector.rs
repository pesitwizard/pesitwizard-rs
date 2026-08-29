//! Storage connectors wired into the node: build a [`Connector`] from stored configuration, and a
//! connectivity-test endpoint. Virtual files reference a connector so transfers are staged to / from
//! S3, SFTP or another local directory.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use pesit_app::http::ApiError;
use pesit_app::store::JsonStore;
use pesit_connector::{
    Connector, LocalConnector, S3Config, S3Connector, SftpConfig, SftpConnector,
};
use serde_json::json;

use crate::api::App;
use crate::model::{tables, ConnectorConfig};

/// Build a live connector from its stored configuration.
pub fn build(store: &JsonStore, id: &str) -> Result<Connector, ApiError> {
    let cfg: ConnectorConfig = store
        .get(tables::CONNECTORS, id)?
        .ok_or_else(|| ApiError::not_found(format!("connector '{id}' not found")))?;
    from_config(&cfg)
}

/// Build a connector from a configuration value.
pub fn from_config(cfg: &ConnectorConfig) -> Result<Connector, ApiError> {
    match cfg.kind.as_str() {
        "s3" => {
            let bucket = cfg
                .bucket
                .clone()
                .filter(|b| !b.is_empty())
                .ok_or_else(|| ApiError::bad_request("S3 connector needs a bucket"))?;
            let s3 = S3Connector::connect(&S3Config {
                bucket,
                region: cfg.region.clone(),
                endpoint: cfg.endpoint.clone(),
                access_key: cfg.access_key.clone(),
                secret_key: cfg.secret_key.clone(),
                path_style: cfg.path_style,
            });
            Ok(Connector::S3(s3))
        }
        "sftp" => {
            let host = cfg
                .host
                .clone()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| ApiError::bad_request("SFTP connector needs a host"))?;
            Ok(Connector::Sftp(SftpConnector::new(SftpConfig {
                host,
                port: if cfg.port == 0 { 22 } else { cfg.port },
                user: cfg.user.clone().unwrap_or_default(),
                password: cfg.password.clone(),
                base_path: cfg.base_path.clone(),
            })))
        }
        _ => Ok(Connector::Local(LocalConnector::new(
            cfg.base_path.clone().unwrap_or_else(|| "/".into()),
        ))),
    }
}

/// Connector routes (merged into the admin router; CRUD is handled by the generic config routes).
pub fn routes() -> Router<Arc<App>> {
    Router::new().route("/api/v1/config/connectors/{id}/test", post(test))
}

async fn test(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let connector = build(&app.store, &id)?;
    match connector.test().await {
        Ok(()) => Ok(Json(json!({ "success": true, "type": connector.kind() }))),
        Err(e) => Ok(Json(json!({ "success": false, "message": e.to_string() }))),
    }
}
